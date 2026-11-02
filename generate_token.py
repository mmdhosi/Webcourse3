"""Offline issuer: run only by the administrator, never exposed as a web endpoint."""
import argparse
import os
from jwt_auth import issue_token

parser = argparse.ArgumentParser()
parser.add_argument('--subject', default='student')
parser.add_argument('--seconds', type=int, default=900)
args = parser.parse_args()
secret = os.environ.get('JWT_SECRET', '').encode()
if len(secret) < 32 or not args.subject.strip() or not 1 <= args.seconds <= 3600:
    parser.error('Set a >=32-byte JWT_SECRET, a subject, and a lifetime of 1..3600 seconds')
print(issue_token(secret, os.environ.get('JWT_ISSUER', 'http-hands-on'),
                  os.environ.get('JWT_AUDIENCE', 'legacy-service'),
                  args.subject, args.seconds))
