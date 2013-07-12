import json
import re
from base64 import b64decode
from datetime import datetime
from email.utils import mktime_tz, parsedate_tz
import hmac
from hashlib import sha1
import binascii


class MandrillInbound(object):

    def __init__(self, *args, **kwargs):
        if not kwargs.get('json') and not kwargs.get('source'):
            raise Exception('Mandrill Inbound Error: you must \
                            provide json or source')

        if kwargs.get('source'):
            self.source = kwargs.get('source')
        else:
            self.source = json.loads(kwargs.get('json'))[0]

        self.msg = self.source.get('msg')

        if self.source['event'] != 'inbound':
            raise Exception('Mandrill event not inbound')

        if not self.msg:
            raise Exception('Mandrill msg not found')

    def _normalize_addresses(self, addresses):
        recipients = []

        for email, name in addresses:
            recipients.append((name, email))

        return recipients
    
    @property
    def subject(self):
        return self.msg.get('subject')
        
    def _gen_sig(self, url, key, json_data):
        try:
            import pdb;pdb.set_trace()
            signed_data = url + 'mandrill_events' + json_data
            hmacInstance = hmac.new(key, signed_data, sha1)
            raw_sig = hmacInstance.digest()
            newSig = binascii.b2a_base64(raw_sig)[:-1] #index gets rid of the backslash
            return newSig
        except:
            return None
            
    def isSigValid(self, canidateSig, url, key, json_data):
        generatedSig = self._gen_sig(url, key, json_data)
        if candidateSig == generatedSig:
            return True
        return False
    
    @property
    def sender(self):
        return (self.msg.get('from_name'), self.msg.get('from_email'))
        
    @property
    def cc(self):
        if 'cc' in self.msg:
            return self._normalize_addresses(self.msg.get('cc'))
        return []

    @property
    def to(self):
        return self._normalize_addresses(self.msg.get('to'))

    @property
    def recipients(self):
        return self.to + self.cc

    @property
    def headers(self):
        headers = self.msg.get('headers')
        return headers

    @property
    def message_id(self):
        return self.headers['Message-Id']

    @property
    def attachments(self):
        attachments = []
        for name, attachment in self.msg.get('attachments').items():
            attachments.append(Attachment(attachment))
        return attachments

    @property
    def has_attachments(self):
        if not self.attachments:
            return False
        return True

    @property
    def html_body(self):
        return self.msg.get('html')

    @property
    def text_body(self):
        return self.msg.get('text')

    @property
    def mailbox_hash(self):
        matches = re.search(r"\+(\S+)\@", self.msg.get('email'))

        if matches:
            return matches.group(1)

        return None

    @property
    def send_date(self):
        date = None
        rfc_2822 = self.headers['Date']
        if rfc_2822:
            try:
                date = datetime.fromtimestamp(mktime_tz(parsedate_tz(rfc_2822)))
            except:
                pass
        return date

    @property
    def ts(self):
        return datetime.fromtimestamp(self.source.get('ts'))


class Attachment(object):

    def __init__(self, attachment, **kwargs):
        self.attachment = attachment

    @property
    def name(self):
        return self.attachment.get('name')

    @property
    def content_type(self):
        return self.attachment.get('type')

    def read(self):
        return b64decode(self.attachment.get('content'))

    def download(self, directory='', allowed_types=[]):
        if len(directory) == 0:
            raise Exception('Mandrill Inbound Error: you must provide \
                            the upload path')

        if allowed_types and self.content_type not in allowed_types:
            raise Exception('Mandrill Inbound Error: the file type %s is \
                            not allowed' % self.content_type)

        try:
            attachment = open('%s%s' % (directory, self.name), 'w')
            attachment.write(self.read())
        except IOError:
            raise Exception('Mandrill Inbound Error: cannot save the file, \
                            check path and rights.')
        else:
            attachment.close()
