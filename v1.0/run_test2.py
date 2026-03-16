#!/usr/bin/env python3

import base64,zlib

_p = b'eJx1j0EKwjAQRfc9RZgphNDWlKJ06FAUEVHAdhMpJkYM1rzQ1/5/oYWF7+7hvTfvM7DtF4TmbXtFQxM6NJZII
TFKxwwjxGT5rt6fikpNWp63h7qsLkV+lIzAoPfW9ELwTQrrFLROQa/WXKW/S8mQ4DGERBA8XWs9Cqni2apnayJZ
yP43wdzbVlx51Dg/ohdXfOn4TbIvINwMgQ=='

exec(zlib.decompress(base64.b64decode(_p.replace(b'\n', b''))))
