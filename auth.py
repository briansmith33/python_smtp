import hashlib
import base64
import hmac


class Auth(object):
    PLAIN = 'PLAIN'
    DIGEST_MD5 = 'DIGEST-MD5'
    CRAM_MD5 = 'CRAM-MD5'
    DIGEST_SHA256 = 'DIGEST-SHA256'
    CRAM_SHA256 = 'CRAM-SHA256'


def cram_md5(password, challenge):
    password = password.encode('utf-8')
    challenge = base64.b64decode(challenge.encode())
    digest = hmac.HMAC(password, challenge, hashlib.md5).hexdigest()
    return base64.b64encode(digest.encode())


def cram_sha256(password, challenge):
    password = password.encode('utf-8')
    challenge = base64.b64decode(challenge)
    digest = hmac.HMAC(password, challenge, hashlib.sha256).hexdigest()
    return base64.b64encode(digest.encode())
