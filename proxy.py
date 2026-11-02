"""Authenticate every HTTP request before forwarding it to a fixed upstream."""
import asyncio
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web
from multidict import CIMultiDict
from yarl import URL

from jwt_auth import InvalidToken, verify_token

HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
       'te', 'trailer', 'transfer-encoding', 'upgrade', 'proxy-connection'}
SETTINGS = web.AppKey('settings', object)
SESSION = web.AppKey('session', aiohttp.ClientSession)


@dataclass(frozen=True)
class Settings:
    secret: bytes
    upstream: str = 'http://legacy:8081'
    issuer: str = 'http-hands-on'
    audience: str = 'legacy-service'

    def __post_init__(self):
        if len(self.secret) < 32:
            raise ValueError('JWT_SECRET must contain at least 32 UTF-8 bytes')
        parsed = urlsplit(self.upstream)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname
                or parsed.username or parsed.password or parsed.query
                or parsed.fragment or parsed.path not in ('', '/')):
            raise ValueError('UPSTREAM_URL must be an HTTP(S) origin without a path')


def clean_headers(headers, extra=()):
    blocked = HOP | set(extra)
    for value in headers.getall('Connection', []):
        blocked.update(x.strip().lower() for x in value.split(','))
    return CIMultiDict((k, v) for k, v in headers.items() if k.lower() not in blocked)


async def forward(request):
    config = request.app[SETTINGS]
    values = request.headers.getall('Authorization', [])
    parts = values[0].split() if len(values) == 1 else []
    try:
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise InvalidToken('Missing bearer token')
        claims = verify_token(parts[1], config.secret, config.issuer, config.audience)
    except InvalidToken:
        return web.json_response({'error': 'A valid Bearer JWT is required'}, status=401,
                                 headers={'WWW-Authenticate': 'Bearer realm="legacy"',
                                          'Cache-Control': 'no-store'})

    # HTTP Upgrade / WebSocket tunneling is outside this HTTP assignment.
    if 'Upgrade' in request.headers or request.method == 'CONNECT':
        return web.json_response({'error': 'Protocol tunneling is unsupported'}, status=501)
    body = await request.read()  # aiohttp enforces the 1 MiB request limit.
    spoofable = {'authorization', 'host', 'content-length', 'forwarded', 'x-authenticated-user'}
    spoofable.update(k.lower() for k in request.headers if k.lower().startswith('x-forwarded-'))
    headers = clean_headers(request.headers, spoofable)
    headers['X-Authenticated-User'] = claims['sub']
    headers['X-Forwarded-For'] = request.remote or ''
    headers['X-Forwarded-Proto'] = request.scheme
    # Concatenation, rather than URL joining, prevents //host/path overriding the origin.
    path = request.raw_path
    if not path.startswith('/'):
        return web.json_response({'error': 'Origin-form request target required'}, status=400)
    target = URL(config.upstream.rstrip('/') + path, encoded=True)
    response = None
    try:
        async with request.app[SESSION].request(
            request.method, target, headers=headers, data=body,
            allow_redirects=False,
        ) as upstream:
            response = web.StreamResponse(status=upstream.status,
                                          headers=clean_headers(upstream.headers))
            await response.prepare(request)
            async for chunk in upstream.content.iter_chunked(65536):
                await response.write(chunk)
            await response.write_eof()
            return response
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        if response is not None and response.prepared:
            # A response has already started: terminate rather than append a second response.
            if request.transport:
                request.transport.close()
            return response
        status = 504 if isinstance(exc, asyncio.TimeoutError) else 502
        return web.json_response({'error': 'Upstream unavailable'}, status=status)


async def client_session(app):
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30, connect=5),
        auto_decompress=False, cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=False, skip_auto_headers={'User-Agent', 'Accept-Encoding', 'Content-Type'},
    ) as session:
        app[SESSION] = session
        yield


def create_app(settings):
    app = web.Application(client_max_size=1024 * 1024)
    app[SETTINGS] = settings
    app.cleanup_ctx.append(client_session)
    app.router.add_route('*', '/{path:.*}', forward)
    return app


if __name__ == '__main__':
    settings = Settings(os.environ.get('JWT_SECRET', '').encode(),
                        os.environ.get('UPSTREAM_URL', 'http://legacy:8081'),
                        os.environ.get('JWT_ISSUER', 'http-hands-on'),
                        os.environ.get('JWT_AUDIENCE', 'legacy-service'))
    web.run_app(create_app(settings), host='0.0.0.0', port=8000, access_log=None,
                handler_args={'auto_decompress': False})
