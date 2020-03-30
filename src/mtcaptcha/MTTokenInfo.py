'''
Class that maps to the JSON TokenInfo
'''


class MTTokenInfo():

    v = None
    code = None
    code_desc = None
    token_id = None
    timestamp_sec = None
    timestamp_iso = None
    hostname = None
    is_dev_host = None
    action = None
    ip = None

    def __init__(self, v: str, code: int, codeDesc: str, tokID: str,
                 timestampSec: int, timestampISO: str, hostname: str,
                 isDevHost: bool, action: str, ip: str) -> None:
        super().__init__()
        self.v = v
        self.code = code
        self.code_desc = codeDesc
        self.token_id = tokID
        self.timestamp_sec = timestampSec
        self.timestamp_iso = timestampISO
        self.hostname = hostname
        self.is_dev_host = isDevHost
        self.action = action
        self.ip = ip
