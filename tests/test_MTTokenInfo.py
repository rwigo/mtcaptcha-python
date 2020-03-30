from mtcaptcha.MTTokenInfo import MTTokenInfo

obj = MTTokenInfo(v="Some value",
                  code=200,
                  codeDesc="Code description",
                  tokID="token_id",
                  timestampSec=1873637687,
                  timestampISO="2020-01-01T10:00:00.000Z",
                  hostname="localhost",
                  isDevHost=True,
                  action="test",
                  ip="127.0.0.1")


def test_MTTokenInfo_v():
    assert obj.v == 'Some value'
    assert obj.v != 'Other value'


def test_MTTokenInfo_code():
    assert obj.code == 200
    assert obj.code != 0