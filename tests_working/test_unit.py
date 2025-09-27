"""
2025:
    This test is attempting to reverse engineer the sigend_request concept.
    This concept no longer has documentation and appears to not work anymore.
"""

# stdlib
import base64
import datetime
import hashlib
import hmac
import json
from typing import Dict
from typing import Optional
from typing import Tuple
import unittest

# local
import facebook_utils as fb

# from facebook_utils.api_versions import API_VERSIONS
# from facebook_utils.exceptions import ApiRatelimitedError
# from facebook_utils.utils import parse_environ
# from facebook_utils.utils import TYPE_CONFIG_PARSED


# ==============================================================================


TODAY = datetime.datetime.today()
APP_RATELIMITED = False
GO_SLOWLY = True


# ------------------------------------------------------------------------------

# https://github.com/mobolic/facebook-sdk/blob/3fa89fec6a20dd070ccf57968c6f89256f237f54/test/test_signed_request.py
FACEBOOK_SIGNED_REQUEST = (
    "Z6pnNcY-TePEBA7IfKta6ipLgrig53M7DRGisKSybBQ."
    "eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImNvZGUiOiJBUURjSXQ2YnhZ"
    "M090T3BSRGtpT1k4UDNlOWgwYzZRNFFuMEFFQnVqR1M3ZEV5LXNtbUt5b3pD"
    "dHdhZy1kRmVYNmRUbi12dVBfQVNtek5RbjlkakloZHJIa0VBMHlLMm16T0Ji"
    "RS1memVoNUh0Vk5UbnpQUDV3Z2VmUkF1bjhvTkQ4S3I3aUd2a3A4Q2EzODJL"
    "NWtqcVl1Z19QV1NUREhqMlY3T2NWaE1GQ2wyWkN2MFk5NnlLUDhfSVAtbnNL"
    "b09kcFVLSU5LMks1SGgxUjZfMkdmMUs1OG5uSnd1bENuSVVRSlhSSU83VEd3"
    "WFJWOVlfa1hzS0pmREpUVzNnTWJ1UGNGc3p0Vkx3MHpyV04yQXE3YWVLVFI2"
    "MFNyeVgzMlBWZkhxNjlzYnUwcnJWLUZMZ2NvMUpBVWlYRlNaY2Q5cVF6WSIs"
    "Imlzc3VlZF9hdCI6MTQ0MTUxNTY1OCwidXNlcl9pZCI6IjEwMTAxNDk2NTUz"
    "NDg2NjExIn0"
)


class TestFacebookUtils_A(unittest.TestCase):
    """
    These are expected to fail as verify_signed_request is busted
    """

    app_id: str = "app_id"
    app_secret: str = "app_secret"
    enable_secretproof: bool = True
    app_scope: str = "app_scope"
    app_domain: str = "app_domain"
    oauth_code_redirect_uri: str = "/oauth-code"
    oauth_token_redirect_uri: str = "/oauth-token"
    fb_api_version: str = "23.0"  # most recent

    def _newHub(self) -> fb.FacebookHub:
        hub = fb.FacebookHub(
            app_id=self.app_id,
            app_secret=self.app_secret,
            enable_secretproof=self.enable_secretproof,
            app_scope=self.app_scope,
            app_domain=self.app_domain,
            oauth_code_redirect_uri=self.oauth_code_redirect_uri,
            oauth_token_redirect_uri=self.oauth_token_redirect_uri,
            fb_api_version=self.fb_api_version,
        )
        return hub

    def test_verify_signed_request(self) -> None:

        hub = self._newHub()

        payload = json.dumps({"hello": "world"})
        # '{"hello": "world"}'

        expected_sig = hmac.new(
            self.app_secret.encode(), msg=payload.encode(), digestmod=hashlib.sha256
        ).digest()
        # b'\xa6m69\xe7eJbc\xeb\x12\x12ps\xf5\x99]c\xb9\xad\xfb\xe9\x14\xce\xb5\x13\x00\xc4[>?`'

        signed_request = (
            b".".join(
                [
                    base64.urlsafe_b64encode(payload.encode()),
                    base64.urlsafe_b64encode(expected_sig),
                ]
            )
        ).decode()

        try:
            result = hub.verify_signed_request(signed_request)  # noqa: F841
            raise ValueError("TypeError should have been raised")
        except TypeError:
            pass
        except Exception:
            raise

    def test_verify_signed_request_b(self) -> None:

        def decode_base64_url(encoded_string):
            padded_string = encoded_string + "===" * (len(encoded_string) % 4 != 0)
            decoded_bytes = base64.urlsafe_b64decode(padded_string)
            decoded_string = decoded_bytes.decode("utf-8")
            return decoded_string

        foo = json.dumps({"hello": "world"})
        # '{"hello": "world"}'

        bar = base64.urlsafe_b64decode(foo + "=" * (4 - len(foo) % 4))

        # these are all testing
        biz = base64.urlsafe_b64encode(bar)
        fip = base64.urlsafe_b64encode(foo.encode())
        fiz = base64.urlsafe_b64decode(fip)

        assert biz
        assert fip
        assert fiz

    def test_verify_signed_request__c(self) -> None:
        def generate_signed_request(_data: Dict) -> str:
            payload_s = json.dumps(_data)
            # '{"hello": "world"}'
            payload_se = base64.urlsafe_b64encode(payload_s.encode())
            signature = hmac.new(
                self.app_secret.encode(),
                msg=payload_se,
                digestmod=hashlib.sha256,
            ).digest()
            signature_se = base64.urlsafe_b64encode(signature)
            signed_request = b".".join((signature_se, payload_se))
            _signed_request = signed_request.decode()
            return _signed_request

        def verify_signed_request(_signed_request: str) -> Tuple[bool, Optional[Dict]]:
            (signature_se, payload_se) = _signed_request.split(".")
            signature_s = base64.urlsafe_b64decode(signature_se)
            assert signature_s
            payload_s = base64.urlsafe_b64decode(payload_se)
            data = json.loads(payload_s)
            return True, data

        data = {"hello": "world"}
        signed_request = generate_signed_request(data)
        print(signed_request)
        _valid, _data = verify_signed_request(signed_request)
        print(_valid, _data)
        assert _data == data

        if False:

            def base64_url_decode(inp: str) -> bytes:
                padding_factor = (4 - len(inp) % 4) % 4
                inp += "=" * padding_factor
                return base64.b64decode(
                    inp.translate(dict(list(zip(list(map(ord, "-_"), "+/")))))
                )

            decoded_signature = base64_url_decode(signed_request)
            assert decoded_signature
