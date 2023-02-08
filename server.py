from auth import cram_md5, cram_sha256, Auth
from dotenv import dotenv_values
from pymongo import MongoClient
from datetime import datetime
from threading import Thread
from queue import Queue
import mysql.connector
import psycopg2
import hashlib
import base64
import socket
import json
import sys
import ssl
config = dotenv_values(".env")

MONGO_CONN_STRING=f"mongodb+srv://{config['MONGO_USER']}:{config['MONGO_PWD']}@{config['MONGO_CLUSTER']}/{config['MONGO_DB']}?retryWrites=true&w=majority"


class Status(object):
    CONN_EST = '220 ESMTP'
    SUCCESS = 250
    FAIL = 550
    ERROR = 500


class Email:
    def __init__(self, date, sender, recipient, subject, message):
        self.date = date
        self.sender = sender
        self.recipient = recipient
        self.subject = subject
        self.message = message


class SMTPServer:
    def __init__(self,
                 domain=config['SMTP_DOMAIN'],
                 host=config['SMTP_HOST'],
                 port=config['SMTP_PORT'],
                 password=config['SMTP_PASS'],
                 authentication_required=True,
                 accepted_relays=None,
                 database='postgres',
                 buffer_size=1024,
                 max_msg_size=14680064):

        if accepted_relays is None:
            accepted_relays = [socket.getfqdn()]

        self.domain = domain
        self.host = host
        self.port = port
        self.addr = (host, port)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.password = password
        self.authentication_required = authentication_required
        self.accepted_relays = accepted_relays
        self.database = database
        self.buffer_size = buffer_size
        self.max_msg_size = max_msg_size
        self.queue = Queue()

    def store(self, sender, recipient, data):
        print(sender)
        print(recipient)
        print(data)

        if self.database is 'postgres':
            conn = psycopg2.connect(
                host=config['PG_HOST'],
                port=config['PG_PORT'],
                database=config['PG_DB'],
                user=config['PG_USER'],
                password=config['PG_PWD'])
            cursor = conn.cursor()

            cursor.execute("""INSERT INTO mail (sender, recipient, data, created_at) 
                                                   VALUES (%s, %s, %s, %s);""",
                           (sender, recipient, json.dumps(data), datetime.now()))
            conn.close()

        if self.database is 'mysql':
            conn = mysql.connector.connect(
                host=config['MYSQL_HOST'],
                port=config['MYSQL_PORT'],
                database=config['MYSQL_DB'],
                user=config['MYSQL_USER'],
                passwd=config['MYSQL_PWD']
            )
            cursor = conn.cursor()

            cursor.execute("""INSERT INTO mail (sender, recipient, data, created_at) 
                                                   VALUES (%s, %s, %s, %s);""",
                           (sender, recipient, json.dumps(data), datetime.now()))
            conn.close()

        if self.database is 'mongodb':
            client = MongoClient(MONGO_CONN_STRING)
            dbname = client[config['MONGO_DB']]
            collection = dbname['mail']
            collection.insert_one({
                'sender': sender,
                'recipient': recipient,
                'data': json.dumps(data),
                'created_at': datetime.now()
            })
            client.close()

    def process_items(self):
        while True:
            if not self.queue.empty():
                item = self.queue.get()

                sender = item['sender']
                recipients = item['recipients']
                data = item['data']
                for recipient in recipients:
                    domain = recipient.split('@')[1]
                    if domain is self.domain:
                        self.store(sender, recipient, data)
                    else:
                        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        conn.connect((domain, 25))

    def filter_data(self, conn, data):
        if sys.getsizeof(data) > self.max_msg_size:
            conn.send(b'554 5.3.4 Message too big for system\r\n')
            return False

        filtered = {}
        for line in data.splitlines():
            if line.lower().startswith('date:'):
                filtered['date'] = line[len('date: '):]

            elif line.lower().startswith('from:'):
                if line.find('"') >= 0:
                    name_start = line[line.index('"') + 1:]
                    name = name_start[:name_start.index('"')]
                    filtered['sender_name'] = name
                filtered['from'] = line[line.find('<') + 1:line.find('>')].lower()

            elif line.lower().startswith('to:'):
                if line.find('"') >= 0:
                    name_start = line[line.index('"') + 1:]
                    name = name_start[:name_start.index('"')]
                    filtered['recipient_name'] = name
                filtered['to'] = line[line.find('<') + 1:line.find('>')].lower()

            elif line.lower().startswith('subject:'):
                filtered['subject'] = line[len('subject: '):]

            else:
                if 'body' not in filtered.keys():
                    filtered['body'] = []
                filtered['body'].append(line)

        return filtered

    def authenticate_session(self, conn, is_tls, method):
        method = method.upper()
        if method == Auth.PLAIN:
            if not is_tls:
                conn.send(b'538 5.7.11 Encryption required for requested authentication mechanism\r\n')
                return False
            conn.send(b'334 \r\n')
            credentials = conn.recv(self.buffer_size).decode().strip()
            if base64.b64decode(credentials) == self.password:
                conn.send(b'235 2.7.0  Authentication Succeeded\r\n')
                return True
            conn.send(b'535 5.7.8  Authentication credentials invalid\r\n')
            return False

        if method == Auth.DIGEST_MD5:
            conn.send(b'334 \r\n')
            credentials = conn.recv(self.buffer_size).decode().strip()
            if base64.b64decode(credentials) == hashlib.md5(self.password).hexdigest():
                conn.send(b'235 2.7.0  Authentication Succeeded\r\n')
                return True
            conn.send(b'535 5.7.8  Authentication credentials invalid\r\n')
            return False

        if method == Auth.CRAM_MD5:
            challenge = base64.b64encode(ssl.RAND_bytes(32)).decode()
            conn.send(b'334 ' + challenge.encode() + b'\r\n')
            credentials = conn.recv(self.buffer_size).decode().strip()
            print(credentials)
            if credentials == cram_md5(self.password, challenge).decode():
                conn.send(b'235 2.7.0  Authentication Succeeded\r\n')
                return True
            conn.send(b'535 5.7.8  Authentication credentials invalid\r\n')
            return False

        if method == Auth.DIGEST_SHA256:
            conn.send(b'334 \r\n')
            credentials = conn.recv(self.buffer_size).decode().strip()
            if base64.b64decode(credentials) == hashlib.sha256(self.password).hexdigest():
                conn.send(b'235 2.7.0  Authentication Succeeded\r\n')
                return True
            conn.send(b'535 5.7.8  Authentication credentials invalid\r\n')
            return False

        if method == Auth.CRAM_SHA256:
            challenge = base64.b64encode(ssl.RAND_bytes(32)).decode()
            conn.send(b'334 ' + challenge.encode() + b'\r\n')
            credentials = conn.recv(self.buffer_size).decode().strip()
            if credentials == cram_sha256(self.password, challenge).decode():
                conn.send(b'235 2.7.0  Authentication Succeeded\r\n')
                return True
            conn.send(b'535 5.7.8  Authentication credentials invalid\r\n')
            return False

        conn.send(b'504 5.5.4 Unrecognized authentication type\r\n')
        return False

    def accept_connection(self, conn, addr):
        conn.send(b'220 smtp.' + self.domain.encode() + b' ESMTP Nexus\r\n')
        sender = None
        recipients = []
        is_tls = False
        is_authenticated = False
        while True:
            msg = conn.recv(self.buffer_size).decode().strip()
            if msg.upper().startswith('QUIT'):
                conn.send(b'221 2.0.0 Goodbye\r\n')
                break

            if msg.upper().startswith('RSET'):
                conn.send(b'250 Ok\r\n')
                sender = ''
                recipients = []
                continue

            if msg.upper().startswith('HELO'):
                relay = msg[len('HELO '):]
                if relay in self.accepted_relays:
                    conn.send(b'250 smtp.' + self.domain.encode() + b' HELO ' + relay.encode() + b'\r\n')
                    continue
                conn.send(b'550 Relay Not Allowed\r\n')
                break

            if msg.upper().startswith('EHLO'):
                relay = msg[len('EHLO '):]
                if relay in self.accepted_relays:
                    conn.send(b'250-smtp2.' + self.domain.encode() + b' EHLO ' + relay.encode() + b'\r\n')
                    if is_tls:
                        conn.send(b'250-AUTH GSSAPI DIGEST-MD5 CRAM-MD5 DIGEST-SHA256 CRAM-SHA256 PLAIN\r\n')
                        conn.send(b'250-SIZE ' + str(self.max_msg_size).encode() + b'\r\n')
                        conn.send(b'250 HELP\r\n')
                    else:
                        conn.send(b'250-AUTH GSSAPI DIGEST-MD5 CRAM-MD5 DIGEST-SHA256 CRAM-SHA256\r\n')
                        conn.send(b'250-SIZE ' + str(self.max_msg_size).encode() + b'\r\n')
                        conn.send(b'250-STARTTLS\r\n')
                        conn.send(b'250 HELP\r\n')
                    continue

            if msg.upper().startswith('HELP'):
                if is_tls:
                    conn.send(b'250-AUTH GSSAPI DIGEST-MD5 CRAM-MD5 DIGEST-SHA256 CRAM-SHA256 PLAIN\r\n')
                    conn.send(b'250-SIZE ' + str(self.max_msg_size).encode() + b'\r\n')
                    conn.send(b'250 HELP\r\n')
                else:
                    conn.send(b'250-AUTH GSSAPI DIGEST-MD5 CRAM-MD5 DIGEST-SHA256 CRAM-SHA256\r\n')
                    conn.send(b'250-SIZE ' + str(self.max_msg_size).encode() + b'\r\n')
                    conn.send(b'250-STARTTLS\r\n')
                    conn.send(b'250 HELP\r\n')
                continue

            if msg.upper().startswith('AUTH'):
                method = msg[len('AUTH '):]
                is_authenticated = self.authenticate_session(conn, is_tls, method)
                continue

            if msg.upper().startswith('SIZE'):
                conn.send(b'250 Ok: ' + str(self.max_msg_size).encode() + b'\r\n')
                continue

            if msg.upper().startswith('STARTTLS'):
                conn.send(b'220 Ready to start TLS\r\n')
                conn = ssl.wrap_socket(conn)
                is_tls = True
                continue

            if msg.upper().startswith('MAIL FROM'):
                if not self.authentication_required or (self.authentication_required and is_authenticated):
                    sender = msg[msg.index('<') + 1:msg.index('>')].lower()
                    conn.send(b'250 <' + sender.encode() + b'> Ok\r\n')
                    continue

                conn.send(b'530 5.7.0 Authentication required\r\n')
                continue

            if msg.upper().startswith('RCPT TO'):
                if not sender:
                    conn.send(b'503 Bad sequence of commands\r\n')
                    continue

                if not self.authentication_required or (self.authentication_required and is_authenticated):
                    recipient = msg[msg.index('<') + 1:msg.index('>')].lower()
                    conn.send(b'250 <' + recipient.encode() + b'> Ok\r\n')
                    recipients.append(recipient)
                    continue

                conn.send(b'530 5.7.0 Authentication required\r\n')
                continue

            if msg.upper().startswith('DATA'):
                if self.authentication_required and not is_authenticated:
                    conn.send(b'530 5.7.0 Authentication required\r\n')
                    continue

                if len(recipients) == 0:
                    conn.send(b'554 No valid recipients\r\n')
                    continue

                conn.send(b'354 End data with <CRLF>.<CRLF>\r\n')
                data = ''
                while True:
                    msg = conn.recv(self.buffer_size).decode()
                    data += msg
                    if msg.endswith('\r\n.\r\n'):
                        break
                    data.replace('\n..', '\n.')

                filtered = self.filter_data(conn, data)
                if filtered:
                    item = {
                        'sender': sender,
                        'recipients': recipients,
                        'data': filtered
                    }

                    self.queue.put(item)
                    conn.send(b'250 Ok: queued as ' + str(self.queue.qsize()).encode() + b'\r\n')

                sender = ''
                recipients = []

        conn.close()

    def relay_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, 25))
        sock.listen(2)
        while True:
            try:
                conn, addr = sock.accept()
                Thread(target=self.accept_connection, args=(conn, addr)).start()
            except KeyboardInterrupt:
                break

    def run(self):
        self.server.bind(self.addr)
        self.server.listen(2)
        Thread(target=self.process_items).start()
        Thread(target=self.relay_server).start()
        while True:
            try:
                conn, addr = self.server.accept()
                Thread(target=self.accept_connection, args=(conn, addr)).start()
            except KeyboardInterrupt:
                break


if __name__ == "__main__":
    server = SMTPServer()
    server.run()
