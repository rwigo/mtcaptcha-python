'''
Class that holds the different state and components during decryption and checking
'''


class DecodedMTTokenInfo():

    # INPUT
    privatekey = None  # transient String  privatekey = null
    token = None  # String token     = null

    # DECODE INTERMEDIATE
    mtChecksum = None  # String mtChecksum    = null
    customerChecksum = None  # String customerChecksum    = null
    siteKey = None  # String siteKey    = null
    randomSeed = None  # String randomSeed    = null
    tokenInfoEncrypted = None  # String tokenInfoEncrypted    = null

    decodeSuccess = None  # boolean decodeSuccess    = False
    decodeErrorMsg = None  # String  decodeErrorMsg    = null

    # DECODE RESULT
    tokenInfoJson = None  # String    tokenInfoJson    = null
    tokenInfoPojo = None  # MTTokenInfo    tokenInfoPojo    = null

    # CHECK RESULT
    checkSuccess = None  # boolean    checkSuccess    = False
    checkFailMsg = None  # String    checkFailMsg    = null

    def __init__(self) -> None:
        super().__init__()

    def init(self, privatekey: str, token: str) -> None:
        self.token = token
        self.privatekey = privatekey
        self.checkSuccess = False
