"""Proxy IPTV pour Home Assistant.

Expose /api/iptv_proxy?token=XXX&url=<url encodée> : Home Assistant télécharge
le flux depuis la maison et le renvoie au navigateur en HTTPS (même origine que
l'interface HA). Ça évite le blocage "mixed content" et les proxys publics.
"""
import hmac
import ipaddress
import logging
from urllib.parse import urlparse

import voluptuous as vol
from aiohttp import ClientError, ClientTimeout, web

from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

DOMAIN = "iptv_proxy"
CONF_TOKEN = "token"

CONFIG_SCHEMA = vol.Schema(
    {DOMAIN: vol.Schema({vol.Required(CONF_TOKEN): cv.string})},
    extra=vol.ALLOW_EXTRA,
)

# En-têtes de la réponse amont recopiés vers le navigateur
PASSTHROUGH_HEADERS = ("Content-Type", "Content-Length", "Content-Range", "Accept-Ranges")
CHUNK_SIZE = 64 * 1024


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.http.register_view(IptvProxyView(hass, config[DOMAIN][CONF_TOKEN]))
    return True


def _is_private_host(host: str) -> bool:
    """Refuse les cibles du réseau local (le proxy ne sert qu'à sortir vers Internet)."""
    if host.lower() in ("localhost", "homeassistant", "homeassistant.local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


class IptvProxyView(HomeAssistantView):
    url = "/api/iptv_proxy"
    name = "api:iptv_proxy"
    # Le lecteur vidéo / hls.js ne peut pas envoyer le jeton HA : on protège par token
    requires_auth = False

    def __init__(self, hass: HomeAssistant, token: str) -> None:
        self._hass = hass
        self._token = token

    async def get(self, request: web.Request) -> web.StreamResponse:
        if not hmac.compare_digest(request.query.get("token", ""), self._token):
            return web.Response(status=403, text="Token invalide")

        target = request.query.get("url", "")
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return web.Response(status=400, text="Paramètre url invalide")
        if _is_private_host(parsed.hostname):
            return web.Response(status=403, text="Cible interdite")

        headers = {
            "User-Agent": request.headers.get("User-Agent", "Mozilla/5.0"),
            # Pas de gzip : sinon Content-Length ne correspond plus aux octets envoyés
            "Accept-Encoding": "identity",
        }
        if "Range" in request.headers:
            headers["Range"] = request.headers["Range"]

        session = async_get_clientsession(self._hass)
        # Pas de délai total : un direct TV peut durer des heures
        timeout = ClientTimeout(total=None, sock_connect=15, sock_read=60)

        resp = None
        try:
            async with session.get(
                target, headers=headers, allow_redirects=True, timeout=timeout
            ) as upstream:
                resp = web.StreamResponse(status=upstream.status)
                for name in PASSTHROUGH_HEADERS:
                    if name in upstream.headers:
                        resp.headers[name] = upstream.headers[name]
                # URL finale après redirections : le lecteur s'en sert pour
                # résoudre les adresses relatives des segments HLS
                resp.headers["X-Final-Url"] = str(upstream.url)
                resp.headers["Access-Control-Allow-Origin"] = "*"
                resp.headers["Access-Control-Expose-Headers"] = (
                    "X-Final-Url, Content-Length, Content-Range"
                )
                resp.headers["Cache-Control"] = "no-store"

                await resp.prepare(request)
                async for chunk in upstream.content.iter_chunked(CHUNK_SIZE):
                    await resp.write(chunk)
                await resp.write_eof()
                return resp
        except (ConnectionResetError, ConnectionAbortedError):
            # Le navigateur a fermé la connexion (changement de chaîne, pause…)
            pass
        except (ClientError, TimeoutError) as err:
            _LOGGER.warning("IPTV proxy: échec pour %s : %s", parsed.hostname, err)
            if resp is None or not resp.prepared:
                return web.Response(status=502, text=f"Erreur serveur IPTV : {err}")
        # Réponse déjà commencée : on ne peut plus en renvoyer une autre
        return resp if resp is not None and resp.prepared else web.Response(status=499)
