from dotenv import dotenv_values
from email import Email
import hashlib
import base64
import socket
import hmac
import ssl
config = dotenv_values(".env")


class Auth(object):
    PLAIN = 'PLAIN'
    DIGEST_MD5 = 'DIGEST-MD5'
    CRAM_MD5 = 'CRAM-MD5'
    DIGEST_SHA256 = 'DIGEST-SHA256'
    CRAM_SHA256 = 'CRAM-SHA256'


class SMTPClient:
    def __init__(self,
                 host=config['SMTP_HOST'],
                 port=config['SMTP_PORT'],
                 password=config['SMTP_PASS'],
                 buffer_size=1024):

        self.host = host
        self.port = port
        self.addr = (host, port)
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.password = password
        self.buffer_size = buffer_size
        self.is_authenticated = False
        self.is_tls = False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.quit()

    def connect(self, addr=None):
        if addr:
            self.client.connect(addr)
        else:
            self.client.connect(self.addr)
        data = self.client.recv(self.buffer_size).decode().strip()
        print(data)

    def helo(self, name=None):
        if name:
            self.client.send(b'HELO '+name.encoded()+b'\r\n')
        else:
            self.client.send(b'HELO '+socket.getfqdn().encode()+b'\r\n')
        data = self.client.recv(self.buffer_size).decode().strip()
        print(data)

    def ehlo(self, name=None):
        if name:
            self.client.send(b'EHLO '+name.encoded()+b'\r\n')
        else:
            self.client.send(b'EHLO '+socket.getfqdn().encode()+b'\r\n')

        while True:
            data = self.client.recv(self.buffer_size).decode().strip()
            print(data)
            if data.startswith('250 '):
                break

    def auth(self, method):
        method = method.upper()
        self.client.send(b'AUTH ' + method.encode() + b'\r\n')
        response = self.client.recv(self.buffer_size).decode().strip()
        print(response)

        if not response.startswith('334'):
            return

        if method == Auth.PLAIN:
            credentials = base64.b64encode(self.password.encode())
            self.client.send(credentials+b'\r\n')
            response = self.client.recv(self.buffer_size).decode().strip()
            print(response)
            if response.startswith('235'):
                self.is_authenticated = True
            return

        if method == Auth.DIGEST_MD5:
            nonce = base64.b64decode(response[len('334 '):])
            credentials = base64.b64encode(hashlib.md5(self.password.encode()+nonce).hexdigest().encode())
            self.client.send(credentials+b'\r\n')
            response = self.client.recv(self.buffer_size).decode().strip()
            print(response)
            if response.startswith('235'):
                self.is_authenticated = True
            return

        if method == Auth.CRAM_MD5:
            challenge = base64.b64decode(response[len('334 '):])
            digest = hmac.HMAC(self.password.encode(), challenge, hashlib.md5).hexdigest()
            credentials = base64.b64encode(digest.encode())
            self.client.send(credentials+b'\r\n')
            response = self.client.recv(self.buffer_size).decode().strip()
            print(response)
            if response.startswith('235'):
                self.is_authenticated = True
            return

    def start_tls(self):
        self.client.send(b'STARTTLS\r\n')
        response = self.client.recv(self.buffer_size).decode().strip()
        print(response)
        self.client = ssl.wrap_socket(self.client)
        self.is_tls = True

    def send(self, email):
        sender = email.sender_addr
        recipients = email.recipients
        message = email.to_string().encode()
        self.client.send(b'MAIL FROM:<'+sender.encode()+b'>\r\n')
        response = self.client.recv(self.buffer_size).decode().strip()
        print(response)
        if not response.startswith('250'):
            return

        for recipient in recipients:
            self.client.send(b'RCPT TO:<' + recipient['address'].encode() + b'>\r\n')
            response = self.client.recv(self.buffer_size).decode().strip()
            print(response)
            if not response.startswith('250'):
                return

        self.client.send(b'DATA \r\n')
        response = self.client.recv(self.buffer_size).decode().strip()
        print(response)
        if not response.startswith('354'):
            return

        self.client.send(message)
        response = self.client.recv(self.buffer_size).decode().strip()
        print(response)

    def max_size(self):
        self.client.send(b'SIZE\r\n')
        response = self.client.recv(self.buffer_size).decode().strip()
        print(response)

    def help(self):
        self.client.send(b'HELP\r\n')
        response = self.client.recv(self.buffer_size).decode().strip()
        print(response)

    def reset(self):
        self.client.send(b'RSET\r\n')
        response = self.client.recv(self.buffer_size).decode().strip()
        print(response)

    def quit(self):
        self.client.send(b'QUIT\r\n')
        response = self.client.recv(self.buffer_size).decode().strip()
        print(response)
