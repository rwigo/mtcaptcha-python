from typing import List, Dict

from mtcaptcha import MTCaptchaTokenDecoderAndChecker


def run_one(privatekey: str, token: str, tokenJson: str,
            expectedDomains: List[str], expectedAction: str,
            isProductionEnv: bool):
    '''
    Run a single test case
    '''
    decoder = MTCaptchaTokenDecoderAndChecker(tokenMaxAgeSeconds=300000000000)

    # -----------DECODE THE TOKEN-------------- #
    di = decoder.decodeMTToken(privatekey, token)

    print("DecodeError:          \t" + str(di.decodeErrorMsg))
    print("MatchesExpectedJson:  \t" + str(tokenJson == di.tokenInfoJson))
    print("TokenInfoJson:        \t" + str(di.tokenInfoJson))
    print("TokenInfoPojo:        \t" + str(di.tokenInfoPojo.__dict__))

    print()

    # ------------CHECK THE TOKEN------------- #
    decoder.checkMTTokenSuccess(di, expectedDomains, expectedAction,
                                isProductionEnv)
    first = di.checkSuccess

    print("CheckFailMsg:\t" + str(di.checkFailMsg))
    print("CheckSuccess:\t" + str(di.checkSuccess))

    decoder.checkMTTokenSuccess(di, expectedDomains, expectedAction,
                                isProductionEnv)
    second = di.checkSuccess

    print("CheckFailMsg:\t" + str(di.checkFailMsg))
    print("CheckSuccess:\t" + str(di.checkSuccess))

    print()
    print()
    return (first, second)


def test_all():
    token1 = "v1(4a73c0ca,8793eb1b,MTPublic-hal9000uJ,adc8dad64a0dbc89c8adbfb315135a9e,eR9SmMaGRafgcFQsIKXvxW8r4nymbmBnlynA4jwsgOt_XO_IaxFa55c1O-qsQJQiNwPilInS4UBN_skpTQa_JyR1-aPWO_PxjlBUJr3djAk5vxQ9cITkL1rf-gRPr-ho8cEfK5AiAc_GJAyeI65UblJ4AZFg7en5dOsSpTHVEA6ISj-q1Ye5fqUf9e0nHQXu01XyIn4xY6QHhqNVSfVKCG3l8MLDuf8EOCyPsmPx8zmxe-5Dd6UJ8F43sWe_PZeDFrxuab5QzUeVDlbXbiWAcQetWAbtaqbrd-3PyydnnlqftfWPfs9ihC6qI6evMmVz5ZCiAnNvO0QX_NuCJYpYDQ**)"
    token1Json = "{\"v\":\"1.0\",\"code\":201,\"codeDesc\":\"valid:captcha-solved\",\"tokID\":\"adc8dad64a0dbc89c8adbfb315135a9e\",\"timestampSec\":981173106,\"timestampISO\":\"2001-02-03T04:05:06Z\",\"hostname\":\"some.example.com\",\"isDevHost\":false,\"action\":\"\",\"ip\":\"10.10.10.10\"}"
    token2 = "v1(0e798202,5d5f720c,MTPublic-hal9000uJ,ed0a316d94101c86886f5408cb0efa91,6i9SkZMiBmDRUfSi2YgZKsFn8_oVAFwqDG9eGW8gfed9-zz_2STbkWIynDodBfMzURDYCaORsbB2X0rU7CqNv8SBKbKv1jnatsJvhtbkwfj75lJxEFf1W_YtZTV1AL_MMl8lyPc5UcTEIWiApANWlnN83KkeC6MONXH_TzGwbjTuKbyW2Sf4HgVH3qiP60snBuKhI9DgXdvYB23mBUduzs1COlpQk4jZa8Tb-WfKEpHzA0VDM7XvQw4HQmtlt7V49JAk7F0qHO-VHFRVH3dLOqLqPPkGCHNAZJbGf79wEUrzL095-OhFfVMa5lVv1gt9vTQmsLUsQZSQfvyW4pnesw**)"
    token2Json = "{\"v\":\"1.0\",\"code\":211,\"codeDesc\":\"valid:ip-whitelisted\",\"tokID\":\"ed0a316d94101c86886f5408cb0efa91\",\"timestampSec\":981173106,\"timestampISO\":\"2001-02-03T04:05:06Z\",\"hostname\":\"more.example.com\",\"isDevHost\":true,\"action\":\"login\",\"ip\":\"10.10.10.10\"}"

    privatekey = "MTPrivat-hal9000uJ-WsPXwe3BatWpGZaEbja2mcO5r7h1h1PkFW2fRoyGRrp4ZH6yfq"
    sitekey = "MTPublic-hal9000uJ"

    expectedDomains = {
        "another.example.com", "some.example.com", "more.example.com"
    }
    expectedAction = ""
    isProductionEnv = False

    assert (True, False) == run_one(privatekey, token1, token1Json,
                                    expectedDomains, '', True)
    assert (False, False) == run_one(privatekey, token1, token1Json,
                                     expectedDomains, '', False)
    assert (False, False) == run_one(privatekey, token1, token1Json,
                                     expectedDomains, 'login', True)
    assert (False, False) == run_one(privatekey, token1, token1Json,
                                     expectedDomains, 'login', False)

    assert (False, False) == run_one(privatekey, token2, token2Json,
                                     expectedDomains, '', True)
    assert (False, False) == run_one(privatekey, token2, token2Json,
                                     expectedDomains, '', False)
    assert (False, False) == run_one(privatekey, token2, token2Json,
                                     expectedDomains, 'login', True)
    assert (True, False) == run_one(privatekey, token2, token2Json,
                                    expectedDomains, 'login', False)

    assert True