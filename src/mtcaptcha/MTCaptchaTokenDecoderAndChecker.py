from typing import List, Dict
from threading import Lock
import time
import math
import base64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Padding
import json
import hashlib

from mtcaptcha.MTTokenInfo import MTTokenInfo
from mtcaptcha.DecodedMTTokenInfo import DecodedMTTokenInfo
'''
Python code to Decrypt and Check MTCaptcha Verified Token
'''


class MTCaptchaTokenDecoderAndChecker():

    def __init__(self,
                 tokenMaxAgeSeconds: int = 300,
                 clockDriftPaddingSeconds: int = 20) -> None:
        super().__init__()
        self._tokenKeyRegistry = dict()
        self._tokenKeyRegistryLock = Lock()
        self._tokenKeyRegistryGCAddCounter = 0
        self._tokenMaxAgeSeconds = tokenMaxAgeSeconds
        self._clockDriftPaddingSeconds = clockDriftPaddingSeconds

    def checkMTTokenSuccess(self, di: DecodedMTTokenInfo,
                            expectedDomains: List[str], exepctedAction: str,
                            isProductionEnv: bool) -> bool:
        '''
        Checks if the DecodedMTTokenInfo is valid. 
        
        @param di			   The DecodedMTTokenInfo object, result from original decode call
        @param expectedDomains  The array of acceptable domains to check with
        @param exepctedAction   The expected action, can be null if not set
        @param isProductionEnv  Checks if token is generated under a Production or Development domain (configured by Sitekey)
        
        The di.checkSuccess		will be updated to true/False depending on the results of this check
        The di.checkFailMsg		will be updated if di.succcess==False
        
        is Thread Safe
        
        @return true, if the token is valid
        '''
        if not di:
            raise ValueError("argument di is null")
        di.checkSuccess = False

        # CHECK IF THERE WAS ANY ERRORs DURING DECODING/DECRYPTION
        if di.decodeErrorMsg != None:
            di.checkFailMsg = "TokenInfo.FailedDecode"
            return False

        # CHECK TOKEN POJO IS NOT NULL
        if di.tokenInfoPojo == None:
            di.checkFailMsg = "TokenInfo.NotFound"
            return False

        # CHECK IF TOKEN IS NOT TOO OLD
        maxAgeSeconds = self._tokenMaxAgeSeconds
        nowSeconds = math.floor(time.time())
        timeBoundLower = nowSeconds - maxAgeSeconds
        timeBoundUpper = nowSeconds + self._clockDriftPaddingSeconds
        if di.tokenInfoPojo.timestamp_sec < timeBoundLower or di.tokenInfoPojo.timestamp_sec > timeBoundUpper:
            di.checkFailMsg = "TokenTime.Expired"
            return False

        # CHECK IF THE TOKEN WAS USED (CHECKED) BEFORE
        if not self.checkTokenGUIDIsNotUsedAndMark(
                di.tokenInfoPojo.token_id, di.tokenInfoPojo.timestamp_sec):
            di.checkFailMsg = "Token.DuplicateUse"
            return False

        # CHECK IF THE DOMAIN IS EXPECTED
        if expectedDomains is not None:
            domainValid = False
            for domain in expectedDomains:
                if domain.lower() == di.tokenInfoPojo.hostname.lower():
                    domainValid = True
                    break
            if not domainValid:
                di.checkFailMsg = "Hostname.NotMatch"
                return False

        # CHECK IF THE ACTION IS EXPECTED
        if exepctedAction is not None and exepctedAction.lower(
        ) != di.tokenInfoPojo.action.lower():
            di.checkFailMsg = "Action.NotMatch"
            return False

        # CHECK IF OF EXPECTED PRODUCTION ENV
        if isProductionEnv is not None and isProductionEnv == di.tokenInfoPojo.is_dev_host:
            di.checkFailMsg = "Env.NotMatch"
            return False

        di.checkSuccess = True
        return di.checkSuccess

    def checkTokenGUIDIsNotUsedAndMark(self, guid: str,
                                       tokenCreateTimeSec: int) -> bool:
        '''
        FOR MULTI SERVER ENVIRONEMNTS, REPLACE BELOW WITH SHARED CACHE IMPLEMENTATION
        '''
        isUsed = False

        # ATOMICALLY CHECK IF THE GUID IS USED/MARKED ALREADY
        with self._tokenKeyRegistryLock:
            prev = self._tokenKeyRegistry.get(guid)
            if prev is None:
                self._tokenKeyRegistry[guid] = tokenCreateTimeSec
                self._tokenKeyRegistryGCAddCounter += 1
            else:
                isUsed = True

        # REMOVE ANY RECORDED TOKEN THAT HAVE EXPIRED
        if self._tokenKeyRegistryGCAddCounter > 200:
            with self._tokenKeyRegistryLock:
                nowSeconds = math.floor(time.time())
                expireThresholdTime = nowSeconds - self._tokenMaxAgeSeconds
                for key, value in self._tokenKeyRegistry.items():
                    if value < expireThresholdTime:
                        del self._tokenKeyRegistry[key]
                        self._tokenKeyRegistryGCAddCounter -= 1
        return not isUsed

    def decodeMTToken(self, privatekey: str, token: str) -> DecodedMTTokenInfo:
        '''
        Decodes and Decrypts the MTCaptcha VerifiedToken
        
        @param privatekey The privatekey 
        @param token		 The verified token string
        
        @return DecodedMTTokenInfo
        decodedMTTokenInfo.decodeSuccess	will be set true/false depending on success or failure of decode
        decodedMTTokenInfo.decodeErrorMsg  will be set with message if DecodedMTTokenInfo.decodeSuccess = False
        '''
        if token is None:
            raise ValueError("argument token is null")
        if privatekey is None:
            raise ValueError("argument privatekey is null")

        di = DecodedMTTokenInfo()
        di.init(privatekey, token)
        try:
            if self.unpackToken(di):
                if self.validateCustomerChecksum(di):
                    if self.decryptToken(di):
                        di.checkSuccess = False
                        di.decodeSuccess = True
        except Exception as excpt:
            di.decodeErrorMsg = type(excpt).__name__ + ':' + str(excpt)
        return di

    def decryptToken(self, di: DecodedMTTokenInfo) -> bool:
        try:
            # REPLACE '*' with '=' character
            tokenInfoBase64Encrypted = di.tokenInfoEncrypted.replace('*', '=')
            # DECODE URLSAFE BASE64 String to byte array
            encryptedbytes = base64.urlsafe_b64decode(tokenInfoBase64Encrypted)
            # GET SINGLE USE DECRYPTION KEY BYTES, WHICH IS GENERATED AS A HASH FROM PRIVATEKEY AND TOKEN RANDOM
            decryptionKeyBytes = self.getOneTimeEncryptionKey(
                di.privatekey, di.randomSeed)
            # CREATE IV (Initializing Vector) for decryption
            ivParameterSpec = decryptionKeyBytes[:AES.block_size]
            # USE ENCRYPTION ALOG AES with CBC and Padding
            cipher = AES.new(decryptionKeyBytes, AES.MODE_CBC, ivParameterSpec)
            # DECRYPT THE DATA BYTES
            decryptedbytes = Padding.unpad(cipher.decrypt(encryptedbytes),
                                           AES.block_size)
            # CONVERT DECRYPTED BYTES TO JSON STRING USING UTF8 ENCODING
            infoJson = bytes.decode(decryptedbytes)
            di.tokenInfoJson = infoJson
            # PARSE JSON STRING TO POJO
            infoObj = MTTokenInfo(**json.loads(infoJson))
            di.tokenInfoPojo = infoObj
            return True
        except Exception as excpt:
            di.decodeErrorMsg = type(excpt).__name__ + ':' + str(excpt)
            return False

    def getOneTimeEncryptionKey(self, privatekey: str,
                                randomSeed: str) -> bytes:
        '''
        Generate 128bit / 16byte key for decryption, 
        As a MD5 Has of the privatekey string and the token's randomseed string
        
        @param privatekey	The privatekey
        @param randomSeed	The randomseed string from the token
        
        @return The binary 128bit decryption key
        
        @throws NoSuchAlgorithmException if MD5 digest is not found 
        '''
        md5 = hashlib.md5()
        md5.update(bytes(privatekey, 'utf-8'))
        md5.update(bytes(randomSeed, 'utf-8'))
        oneTimeKey = md5.digest()
        return oneTimeKey

    def validateCustomerChecksum(self, di: DecodedMTTokenInfo) -> bool:
        '''
        Validate the checksum matches and the token is not tampered
        
        @param di The DecodedMTTokenInfo
        
        @return true if the token has not been tampered and matches checksum
        '''
        # Convert all token text components to bytes using UTF8 encoding
        # CustomerCheckSum  = MD5( [privatekey] + [SiteKey] + [Random Seed] + [Encrypted TokenInfo] ) .toHexLowercase() .substring(0,8)
        privatekeyBytes = bytes(di.privatekey, 'utf-8')
        sitekeyBytes = bytes(di.siteKey, 'utf-8')
        randomBytes = bytes(di.randomSeed, 'utf-8')
        encinfoBytes = bytes(di.tokenInfoEncrypted, 'utf-8')
        try:
            md5 = hashlib.md5()

            md5.update(privatekeyBytes)
            md5.update(sitekeyBytes)
            md5.update(randomBytes)
            md5.update(encinfoBytes)

            md5bytes = md5.digest()
            md5hex = md5bytes.hex()

            calcChecksum = md5hex[0:8]

            if calcChecksum != di.customerChecksum:
                di.decodeErrorMsg = "MalformedToken.CustomerChecksum"
                return False
            else:
                return True
        except Exception as excpt:
            di.decodeErrorMsg = type(excpt).__name__ + ':' + str(excpt)
            return False

    def unpackToken(self, di: DecodedMTTokenInfo) -> bool:
        '''
        Parse and unpack the token into its components

        @param di The DecodedMTTokenInfo

        @return true if the token matches format and is successfully parsed into its components
        '''
        if not isinstance(di.token, str):
            di.decodeErrorMsg = "Token is not a str"
            return False

        len_of_token = len(di.token)
        min_len_of_token = len(
            "v1(xxxxxxxx,yyyyyyyy,MTPublic-zzzzzzzzz,rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr,iiiii)"
        )
        max_len_of_token = 1200
        if len_of_token == 0:
            di.decodeErrorMsg = "EmptyToken"
            return False
        # Check token length within allowed range
        if len_of_token < min_len_of_token or max_len_of_token < len_of_token:
            di.decodeErrorMsg = "MalformedToken.TokenLength"
            return False

        # check token envelope
        if not (di.token.startswith("v1(") and di.token.endswith(")")):
            di.decodeErrorMsg = "MalformedToken.Envelope"
            return False

        # remove envelop 'v1(' and ')'
        noEnvelopToken = di.token[3:-1]
        tokenParts = noEnvelopToken.split(',')
        if len(tokenParts) != 5:
            di.decodeErrorMsg = "MalformedToken.5Parts"
            return False

        di.mtChecksum = tokenParts[0]
        di.customerChecksum = tokenParts[1]
        di.siteKey = tokenParts[2]
        di.randomSeed = tokenParts[3]
        di.tokenInfoEncrypted = tokenParts[4]

        if len(di.mtChecksum) != 8:
            di.decodeErrorMsg = "MalformedToken.MTCheckSumLength"
            return False

        if len(di.customerChecksum) != 8:
            di.decodeErrorMsg = "MalformedToken.CustomerCheckSumLength"
            return False

        if len(di.randomSeed) != 32:
            di.decodeErrorMsg = "MalformedToken.RandomSeedLength"
            return False

        if len(di.siteKey) < 16:
            di.decodeErrorMsg = "MalformedToken.SiteKeyLength"
            return False

        if len(di.tokenInfoEncrypted) < 6:
            di.decodeErrorMsg = "MalformedToken.EncryptedInfoLength"
            return False

        return True
