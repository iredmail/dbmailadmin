# encoding: utf-8

# Author: Zhang Huangbin <zhb@iredmail.org>

import email
from email.Header import decode_header

def _decodeHeaders(msg, defaultCharacterSet='ascii'):
    """Decode message into (header, value) pairs."""

    # Get all mail headers.
    headers = msg.keys()

    # List of {header: value}. Sample:
    # [
    #   {'From': 'sender@domain.ltd', 'To': 'recipient@example.com',},
    # ]
    headers_values = []

    for h in headers:
        # Skip non-exist headers.
        if not h in msg.keys():
            continue

        try:
            # Decode header value to list of (decoded_string, charset) pairs.
            # Convert into unicode.
            header_value = u' '.join([
                unicode(text, charset or defaultCharacterSet)
                 for text, charset in decode_header(msg[h])
            ])
            headers_values += [{h: header_value}]
        except Exception, e:
            pass

    return headers_values

def _getCharsetOfMessagePart(part, default="ascii"):
    """Get charset of message part."""

    try:
        if part.get_content_charset():
            return part.get_content_charset()
        elif part.get_charset():
            return part.get_charset()
    except Exception, e:
        pass

    return default

def parseRawMessage(msg):
    '''Read RAW message from string. Return tuple of:

    list of {header: value}
    string of plain mail body
    list of attachment file names
    '''

    # Get all mail headers. Sample:
    # [{'From': 'sender@xx.com'}, {'To': 'recipient@xx.net'}]
    mailHeaders = []

    # Get decoded content of mail body.
    mailBody = ''

    # Get list of attachment names.
    mailAttachments = []

    msg = email.message_from_string(msg)

    # Get all headers.
    for i in _decodeHeaders(msg):
        for k in i.keys():
            mailHeaders += [(k, i[k])]

    # Get decoded content of mail body and list of attachments.
    for part in msg.walk():
        # multipart/* are just containers
        if part.get_content_maintype() == 'multipart':
            continue

        # String or None.
        filename = part.get_filename()
        try:
            if filename is None:
                # Plain text, not an attachment.
                mailBody += unicode(
                    part.get_payload(decode=True),
                    _getCharsetOfMessagePart(part),
                    'replace',
                )
            else:
                mailAttachments += [filename]
        except Exception, e:
            pass

    return (mailHeaders, mailBody, mailAttachments)
