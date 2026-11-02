"""Small, deliberately HS256-only JWT profile for this assignment."""
import base64
import hashlib
import hmac
import json
import re
import time


class InvalidToken(ValueError):
    pass


def encode_part(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def decode_part(value):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise InvalidToken('Invalid base64url')
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    if encode_part(raw) != value:
        raise InvalidToken('Noncanonical base64url')
    return raw


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidToken('Duplicate JSON key')
        result[key] = value
    return result


def issue_token(secret, issuer, audience, subject, lifetime=900):
    now = int(time.time())
    header = {'alg': 'HS256', 'typ': 'JWT'}
    claims = {'iss': issuer, 'aud': audience, 'sub': subject,
              'iat': now, 'nbf': now, 'exp': now + lifetime}
    parts = [encode_part(json.dumps(x, separators=(',', ':')).encode())
             for x in (header, claims)]
    signed = '.'.join(parts)
    return signed + '.' + encode_part(hmac.digest(secret, signed.encode(), 'sha256'))


def verify_token(token, secret, issuer, audience):
    try:
        if len(token) > 8192:
            raise InvalidToken('Token too long')
        header_part, claims_part, signature_part = token.split('.')
        header = json.loads(decode_part(header_part), object_pairs_hook=unique_object)
        if header != {'alg': 'HS256', 'typ': 'JWT'}:
            raise InvalidToken('Unsupported JWT header')
        expected = hmac.digest(secret, (header_part + '.' + claims_part).encode(), 'sha256')
        if not hmac.compare_digest(expected, decode_part(signature_part)):
            raise InvalidToken('Invalid signature')
        claims = json.loads(decode_part(claims_part), object_pairs_hook=unique_object)
        if not isinstance(claims, dict):
            raise InvalidToken('Claims must be an object')
        for name in ('exp', 'nbf', 'iat'):
            if type(claims.get(name)) is not int:
                raise InvalidToken('Missing or invalid time claim')
        now = time.time()
        if claims['exp'] <= now or claims['nbf'] > now or claims['iat'] > now:
            raise InvalidToken('Invalid token time')
        if claims['exp'] <= claims['iat'] or claims['nbf'] >= claims['exp']:
            raise InvalidToken('Invalid token lifetime')
        if claims.get('iss') != issuer or claims.get('aud') != audience:
            raise InvalidToken('Invalid issuer or audience')
        if not isinstance(claims.get('sub'), str) or not claims['sub'].strip():
            raise InvalidToken('Missing subject')
        return claims
    except (ValueError, TypeError, UnicodeError, KeyError, RecursionError) as exc:
        raise InvalidToken('Invalid JWT') from exc
