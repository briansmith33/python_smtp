from datetime import datetime, timezone


class Email:
    def __init__(self,
                 sender_name=None,
                 sender_addr=None,
                 recipients=None,
                 cc=None,
                 bcc=None,
                 subject=None,
                 message=None):

        if bcc is None:
            bcc = []

        if cc is None:
            cc = []

        if recipients is None:
            recipients = []

        self.sender_name = sender_name
        self.sender_addr = sender_addr
        self.recipients = recipients
        self.cc = cc
        self.bcc = bcc
        self.additional_headers = []
        self.subject = subject
        self.message = message

    def add_recipient(self, name, address):
        self.recipients.append({'name': name, 'address': address})

    def add_cc(self, name, address):
        self.cc.append({'name': name, 'address': address})

    def add_bcc(self, name, address):
        self.bcc.append({'name': name, 'address': address})

    def add_header(self, key, value):
        self.additional_headers.append({'key': key, 'value': value})

    def to_string(self):
        sender_name = f' "{self.sender_name}"' if self.sender_name else ''
        date = datetime.now(timezone.utc).astimezone().strftime('%a, %d %b %Y %X %z')
        subject = self.subject if self.subject else ''
        message = 'From:'+sender_name + f' <{self.sender_addr}>\r\n'
        message += 'To:'
        for recipient in self.recipients:
            recipient_name = f' "' + recipient['name'] + '"' if 'name' in recipient.keys() and recipient['name'] else ''
            message += recipient_name + f" <{recipient['address']}>,"
        message = message[:-1]
        message += '\r\n'

        if self.cc:
            message += 'Cc:'
            for recipient in self.cc:
                recipient_name = f' "'+recipient['name']+'"' if 'name' in recipient.keys() and recipient['name'] else ''
                message += recipient_name + f" <{recipient['address']}>,"
            message = message[:-1]
            message += '\r\n'

        if self.bcc:
            message += 'Bcc:'
            for recipient in self.bcc:
                recipient_name = f' "'+recipient['name']+'"' if 'name' in recipient.keys() and recipient['name'] else ''
                message += recipient_name + f" <{recipient['address']}>,"
            message = message[:-1]
            message += '\r\n'

        for header in self.additional_headers:
            message += header['key']+": "+header['value']+'\r\n'

        message += 'Date: ' + date + '\r\n'
        message += 'Subject: ' + subject + '\r\n'
        message += f'{self.message}\r\n.\r\n'
        return message
