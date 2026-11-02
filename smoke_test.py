"""End-to-end checks against the REAL running Docker Compose stack (Python stdlib only)."""
import json
import subprocess
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(NoRedirect)


def request(path, token=None, method='GET', data=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request('http://127.0.0.1' + path, data=data, headers=headers, method=method)
    try:
        response = opener.open(req, timeout=15)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return response.status, response.headers, response.read()


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print('PASS:', message)


def generate(lifetime):
    code = ('import os; from jwt_auth import issue_token; '
            'print(issue_token(os.environ["JWT_SECRET"].encode(), '
            'os.environ["JWT_ISSUER"], os.environ["JWT_AUDIENCE"], "student", '
            + str(lifetime) + '))')
    return subprocess.check_output(
        ['docker', 'compose', 'exec', '-T', 'proxy', 'python', '-c', code], text=True).strip()


if __name__ == '__main__':
    token = generate(300)
    check(request('/get')[0] == 401, 'missing token rejected')
    check(request('/get', 'invalid')[0] == 401, 'malformed token rejected')
    check(request('/get', generate(-1))[0] == 401, 'expired token rejected')
    parts = token.split('.')
    parts[2] = ('A' if parts[2][0] != 'A' else 'B') + parts[2][1:]
    check(request('/get', '.'.join(parts))[0] == 401, 'tampered signature rejected')
    status, _, body = request('/get?course=internet&item=1&item=2', token)
    result = json.loads(body)
    check(status == 200 and result['args']['item'] == ['1', '2'], 'real httpbin GET and query')
    keys = {name.lower() for name in result['headers']}
    check('authorization' not in keys, 'JWT stripped before upstream')
    status, _, body = request('/post', token, 'POST', b'{"message":"hello"}')
    check(status == 200 and json.loads(body)['json']['message'] == 'hello', 'JSON POST preserved')
    check(request('/status/418', token)[0] == 418, 'upstream status preserved')
    status, headers, _ = request('/redirect/1', token)
    check(status == 302 and 'Location' in headers, 'redirect returned without following')
    check(request('/get', token, 'HEAD')[0] == 200, 'HEAD supported')
    mapping = subprocess.run(['docker', 'compose', 'port', 'legacy', '8081'],
                             text=True, capture_output=True)
    check(not mapping.stdout.strip(), 'legacy port not published on host')
    print('All Docker smoke checks passed.')
