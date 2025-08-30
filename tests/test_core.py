# stdlib
import datetime
import os
import time
from typing import Callable
from typing import Optional
from typing import TYPE_CHECKING
import unittest
from urllib.parse import quote_plus

# local
import facebook_utils as fb
from facebook_utils.api_versions import API_VERSIONS
from facebook_utils.exceptions import ApiRatelimitedError
from facebook_utils.utils import parse_environ
from facebook_utils.utils import TYPE_CONFIG_PARSED


# ==============================================================================


TODAY = datetime.datetime.today()
APP_RATELIMITED = False
GO_SLOWLY = True


# ------------------------------------------------------------------------------


class _TestVersionedAPI(object):
    """
    mixin to ensure we do not test against old versions
    """

    fb_api_version: Optional[str] = None

    def setUp(self):
        if self.fb_api_version:
            if self.fb_api_version not in API_VERSIONS:
                raise ValueError(
                    "Unrecognized fb_api_version: %s" % self.fb_api_version
                )
            (_api_start, _api_end) = API_VERSIONS[self.fb_api_version]
            if _api_end and (_api_end < TODAY.date()):
                raise unittest.SkipTest(
                    "Skipping Test against Facebook API v%s; Support ended %s"
                    % (self.fb_api_version, _api_end)
                )


class _TestFacebookUtils_Authenticated_Core(_TestVersionedAPI):
    FB_UTILS_ENV: TYPE_CONFIG_PARSED
    expect_email_in_profile: bool = True  # via app permissions config on fb
    expect_name_in_profile: bool = False  # via app permissions config on fb

    # via unittest.TestCase
    assertEqual: Callable
    assertFalse: Callable
    assertIn: Callable
    assertNotIn: Callable
    assertRaises: Callable
    assertTrue: Callable

    def _newHub(self) -> fb.FacebookHub:
        """
        We need the following env variables set:
            FBUTILS_APP_ID
            FBUTILS_APP_SECRET
            FBUTILS_ENABLE_SECRETPROOF

            FBUTILS_APP_DOMAIN
            FBUTILS_ACCESS_TOKEN*

        Note:
            *FBUTILS_ACCESS_TOKEN can be a user access token (vs an app or page token)
            we just need the ability to test some actions that require an access token.
        """
        _REQUIRED_ENV = [
            "FBUTILS_APP_ID",
            "FBUTILS_APP_SECRET",
            "FBUTILS_ENABLE_SECRETPROOF",
            "FBUTILS_ACCESS_TOKEN",
            "FBUTILS_APP_DOMAIN",
        ]
        self.FB_UTILS_ENV = parse_environ(requires=_REQUIRED_ENV)

        # assured by parse_environ above
        app_id = self.FB_UTILS_ENV["app_id"]
        app_secret = self.FB_UTILS_ENV["app_secret"]
        enable_secretproof = self.FB_UTILS_ENV["enable_secretproof"]
        app_domain = self.FB_UTILS_ENV["app_domain"]

        if TYPE_CHECKING:
            assert isinstance(app_id, str)
            assert isinstance(app_secret, str)
            assert isinstance(enable_secretproof, bool)
            assert isinstance(app_domain, str)

        hub = fb.FacebookHub(
            app_id=app_id,
            app_secret=app_secret,
            enable_secretproof=enable_secretproof,
            app_scope="email",
            app_domain=app_domain,
            oauth_code_redirect_uri="https://%s/oauth-code" % app_domain,
            oauth_token_redirect_uri="https://%s/oauth-token" % app_domain,
            fb_api_version=self.fb_api_version,
        )
        return hub

    def _fb_api_base__dialog(self) -> str:
        return "https://www.facebook.com/dialog"

    def test_oauth_code__url_dialog(self):
        hub = self._newHub()
        url = hub.oauth_code__url_dialog()
        fb_api_base_dialog = self._fb_api_base__dialog()
        app_domain = self.FB_UTILS_ENV["app_domain"]
        if TYPE_CHECKING:
            assert isinstance(app_domain, str)
        self.assertEqual(
            url,
            "%(FB_API_BASE_DIALOG)s/oauth?client_id=%(FBUTILS_APP_ID)s&scope=email&redirect_uri=https%%3A%%2F%%2F%(FBUTILS_APP_DOMAIN)s%%2Foauth-code"
            % {
                "FBUTILS_APP_ID": hub.app_id,
                "FBUTILS_APP_DOMAIN": quote_plus(app_domain),
                "FB_API_BASE_DIALOG": fb_api_base_dialog,
            },
        )

    def test_oauth_code__url_dialog__custom_redirect(self):
        hub = self._newHub()
        app_domain = self.FB_UTILS_ENV["app_domain"]
        if TYPE_CHECKING:
            assert isinstance(app_domain, str)
        url = hub.oauth_code__url_dialog(
            redirect_uri="https://%(FBUTILS_APP_DOMAIN)s/oauth-code-custom"
            % {"FBUTILS_APP_DOMAIN": quote_plus(app_domain)}
        )
        fb_api_base_dialog = self._fb_api_base__dialog()
        self.assertEqual(
            url,
            "%(FB_API_BASE_DIALOG)s/oauth?client_id=%(FBUTILS_APP_ID)s&scope=email&redirect_uri=https%%3A%%2F%%2F%(FBUTILS_APP_DOMAIN)s%%2Foauth-code-custom"
            % {
                "FBUTILS_APP_ID": hub.app_id,
                "FBUTILS_APP_DOMAIN": quote_plus(app_domain),
                "FB_API_BASE_DIALOG": fb_api_base_dialog,
            },
        )

    def test_oauth_code__url_custom_scope(self):
        hub = self._newHub()
        url = hub.oauth_code__url_dialog(scope="email,user_birthday")
        fb_api_base_dialog = self._fb_api_base__dialog()
        app_domain = self.FB_UTILS_ENV["app_domain"]
        if TYPE_CHECKING:
            assert isinstance(app_domain, str)
        self.assertEqual(
            url,
            "%(FB_API_BASE_DIALOG)s/oauth?client_id=%(FBUTILS_APP_ID)s&scope=email,user_birthday&redirect_uri=https%%3A%%2F%%2F%(FBUTILS_APP_DOMAIN)s%%2Foauth-code"
            % {
                "FBUTILS_APP_ID": hub.app_id,
                "FBUTILS_APP_DOMAIN": quote_plus(app_domain),
                "FB_API_BASE_DIALOG": fb_api_base_dialog,
            },
        )

    def test_oauth_code__url_access_token__fails_without_code(self):
        hub = self._newHub()
        self.assertRaises(TypeError, lambda: hub.oauth_code__url_access_token())

    def test_oauth_code__get_access_token_and_profile__fails_without_code(self):
        hub = self._newHub()
        self.assertRaises(
            TypeError, lambda: hub.oauth_code__get_access_token_and_profile()
        )

    def test_oauth_code__oauth_code__get_access_token__fails_without_code(self):
        hub = self._newHub()
        self.assertRaises(TypeError, lambda: hub.oauth_code__get_access_token())

    def test_access_token_exchange_manual(self):
        # python -munittest tests.TestFacebookUtils_Authenticated.test_access_token_exchange_manual
        hub = self._newHub()
        url_exchange = hub.oauth__url_extend_access_token(
            access_token=self.FB_UTILS_ENV["access_token"]
        )
        fb_data = hub.api_proxy(url=url_exchange, expected_format="json.load")
        if GO_SLOWLY:
            time.sleep(1)
        access_token = fb_data["access_token"]
        self.assertTrue(access_token)

    def test_access_token_exchange_graph(self):
        hub = self._newHub()
        response = hub.graph__extend_access_token(
            access_token=self.FB_UTILS_ENV["access_token"]
        )
        if GO_SLOWLY:
            time.sleep(1)
        self.assertTrue(response["access_token"])

    def test_graph_me(self):
        hub = self._newHub()
        url_me = hub.graph__url_me_for_access_token(
            access_token=self.FB_UTILS_ENV["access_token"]
        )
        fb_data = hub.api_proxy(url=url_me, expected_format="json.load")
        if GO_SLOWLY:
            time.sleep(1)
        self.assertTrue(fb_data)

    def test_graph__get_profile_for_access_token(self):
        hub = self._newHub()
        fb_data = hub.graph__get_profile_for_access_token(
            access_token=self.FB_UTILS_ENV["access_token"]
        )
        if GO_SLOWLY:
            time.sleep(1)
        self.assertTrue(fb_data)

        self.assertIn("id", fb_data)

        if self.expect_email_in_profile:
            self.assertIn("email", fb_data)

        if self.expect_name_in_profile:
            self.assertIn("name", fb_data)

        if not self.expect_email_in_profile or not self.expect_name_in_profile:
            fb_data2 = hub.graph__get_profile_for_access_token(
                access_token=self.FB_UTILS_ENV["access_token"], fields="email,name"
            )
            if GO_SLOWLY:
                time.sleep(1)
            self.assertTrue(fb_data2)
            self.assertIn("email", fb_data2)
            self.assertIn("id", fb_data2)
            self.assertIn("name", fb_data2)

    def test_graph__get_feed_single(self):
        hub = self._newHub()
        FB_LIMIT_LINKS = 10
        FB_FIELDS = "id,from,message,comments,created_time,link,caption,description"
        access_token = self.FB_UTILS_ENV["access_token"]
        if TYPE_CHECKING:
            assert access_token is None or isinstance(access_token, str)
        fb_data = hub.api_proxy(
            url="""https://graph.facebook.com/me/feed?fields=%s""" % FB_FIELDS,
            expected_format="json.load",
            access_token=access_token,
        )
        if GO_SLOWLY:
            time.sleep(1)
        self.assertTrue(fb_data)
        # TODO - test to see we have these fields!

    def test_graph__get_batched(self):
        hub = self._newHub()
        FB_LIMIT_LINKS = 1
        FB_LIMIT_HOME = 1
        FB_FIELDS = "id,from,message,comments,created_time,link,caption,description"
        fb_post_data = {
            "access_token": self.FB_UTILS_ENV["access_token"],
            "batch": [
                {"method": "GET", "relative_url": "/me/permissions"},
                {
                    "method": "GET",
                    "relative_url": "/me/feed?limit=%s&fields=%s"
                    % (FB_LIMIT_LINKS, FB_FIELDS),
                },
            ],
        }
        fb_data = hub.api_proxy(expected_format="json.load", post_data=fb_post_data)
        if GO_SLOWLY:
            time.sleep(1)
        self.assertTrue(fb_data)
        # TODO - test to see we have the fields present

    def test_graph__no_url__get_batched(self):
        hub = self._newHub()
        FB_LIMIT_LINKS = 1
        FB_LIMIT_HOME = 1
        # FB_FIELDS = 'id,from,message,comments,created_time,link,caption'
        FB_FIELDS = sorted(
            set(
                "id,name,description,message,created_time,caption,description".split(
                    ","
                )
            )
        )
        fb_post_data = {
            "access_token": self.FB_UTILS_ENV["access_token"],
            "batch": [
                {"method": "GET", "relative_url": "/me/permissions"},
                {
                    "method": "GET",
                    "relative_url": "/me/feed?limit=%s&fields=%s"
                    % (FB_LIMIT_LINKS, FB_FIELDS),
                },
            ],
        }
        fb_data = hub.api_proxy(expected_format="json.load", post_data=fb_post_data)
        if GO_SLOWLY:
            time.sleep(1)
        self.assertTrue(fb_data)
        # TODO - test to see we have the batch fields present

    @unittest.skipIf(APP_RATELIMITED, "APP_RATELIMITED")
    def test_graph__url__upgrades(self):
        hub = self._newHub()
        access_token = self.FB_UTILS_ENV["access_token"]
        if TYPE_CHECKING:
            assert access_token is None or isinstance(access_token, str)
        fb_data = hub.api_proxy(
            url="/me/permissions",
            access_token=access_token,
        )
        if GO_SLOWLY:
            time.sleep(1)
        # the payload is something like
        #    {u'data': [{u'permission': u'user_posts', u'status': u'granted'},
        #               {u'permission': u'email', u'status': u'granted'},
        #               {u'permission': u'public_profile', u'status': u'granted'}
        #               ]
        #     }
        self.assertIn("data", fb_data)
        self.assertIn("permission", fb_data["data"][0])

        # make sure we tracked a _last_response
        self.assertTrue(hub._last_response)
        self.assertFalse(hub.last_response_is_ratelimited)

    @unittest.skipIf(APP_RATELIMITED, "APP_RATELIMITED")
    def test_graph__no_url__get_object_single(self):
        urls = {"https://example.com": "482839044422"}
        url = list(urls.keys())[0]
        hub = self._newHub()
        get_data = {
            "ids": url,
            "fields": "id,og_object",
        }
        # in 2.3 we didn't need to pass in an access token. in 2.4 we do.
        access_token = self.FB_UTILS_ENV["access_token"]
        if TYPE_CHECKING:
            assert access_token is None or isinstance(access_token, str)
        try:
            fb_data = hub.api_proxy(
                expected_format="json.load",
                get_data=get_data,
                access_token=access_token,
            )
            if GO_SLOWLY:
                time.sleep(1)
        except ApiRatelimitedError:
            print("ApiRatelimitedError")
            APP_RATELIMITED = True
            raise
        self.assertIn("og_object", fb_data[url])
        self.assertIn("id", fb_data[url]["og_object"])
        self.assertEqual(fb_data[url]["og_object"]["id"], urls[url])
        # make sure we tracked a _last_response
        self.assertTrue(hub._last_response)
        self.assertFalse(hub.last_response_is_ratelimited)

    def test_graph__bad_url(self):
        hub = self._newHub()

        def _bad_url_insecure():
            fb_data = hub.api_proxy(url="http://example.com")

        def _bad_url_wtf():
            fb_data = hub.api_proxy(url="wtf")

        self.assertRaises(fb.exceptions.ApiError, lambda: _bad_url_insecure())
        if GO_SLOWLY:
            time.sleep(1)
        self.assertRaises(fb.exceptions.ApiError, lambda: _bad_url_wtf())
        if GO_SLOWLY:
            time.sleep(1)

    @unittest.skipIf(APP_RATELIMITED, "APP_RATELIMITED")
    def test_permissions_access(self):
        def _validate_payload(_payload):
            self.assertIn("data", _payload)
            _has_email = None
            for datum in _payload["data"]:
                if datum["permission"] == "email":
                    _has_email = True if datum["status"] == "granted" else False
            self.assertTrue(_has_email)

        # SETUP start
        hub = self._newHub()
        try:
            fb_data = hub.graph__get_profile_for_access_token(
                access_token=self.FB_UTILS_ENV["access_token"]
            )
            if GO_SLOWLY:
                time.sleep(1)
        except ApiRatelimitedError:
            print("ApiRatelimitedError")
            APP_RATELIMITED = True
            raise
        self.assertTrue(fb_data)
        user_id = fb_data["id"]
        # SETUP end

        # this is one method of getting permissions
        url = "/%s/permissions" % user_id
        access_token = self.FB_UTILS_ENV["access_token"]
        if TYPE_CHECKING:
            assert access_token is None or isinstance(access_token, str)
        fb_data__permissions = hub.api_proxy(
            url,
            access_token=access_token,
        )
        if GO_SLOWLY:
            time.sleep(1)
        _validate_payload(fb_data__permissions)

        # this is another method...
        fb_data__permissions_alt = hub.graph__get_profile_for_access_token(
            access_token=self.FB_UTILS_ENV["access_token"],
            user=user_id,
            action="permissions",
            # fields = 'id,name,email',  # don't pass the profile elements in to the action. otherwise it blanks
        )
        if GO_SLOWLY:
            time.sleep(1)
        _validate_payload(fb_data__permissions)

    def test_feed_elements(self):
        pass


class _TestFacebookUtils_UnAuthenticated(_TestVersionedAPI):

    # via unittest.testCase
    assertEqual: Callable
    assertFalse: Callable
    assertIn: Callable
    assertTrue: Callable

    def _newHub(self) -> fb.FacebookHub:
        """
        this is for unauthenticated tests
        """
        env = os.environ
        hub = fb.FacebookHub(
            unauthenticated_hub=True, fb_api_version=self.fb_api_version
        )
        return hub

    def test_graph__get_object_single(self):
        urls = {"https://example.com": "482839044422"}
        url = list(urls.keys())[0]
        hub = self._newHub()
        get_data = {"ids": url}
        fb_data = hub.api_proxy(
            url="https://graph.facebook.com",
            expected_format="json.load",
            get_data=get_data,
        )
        if GO_SLOWLY:
            time.sleep(1)
        self.assertIn(url, fb_data)
        self.assertIn("og_object", fb_data[url])
        self.assertIn("id", fb_data[url]["og_object"])
        self.assertEqual(fb_data[url]["og_object"]["id"], urls[url])

        # make sure we tracked a _last_response
        self.assertTrue(hub._last_response)
        self.assertFalse(hub.last_response_is_ratelimited)

    def test_graph__get_object_multiple(self):
        """
        facebook's API is a little less than stellar.
            facebook.com SHOULD be ? 405613579725? however sometimes it returns `10151063484068358`, which is the wrong object (http and https)
                        it also returns 411149314032
            http://example.com comes back as either 395320319544 or 389691382139
            I filed bug reports for both
        """
        # url: facebook opengraph id
        urls = {
            "http://example.com": (
                "395320319544",
                "389691382139",
            ),  # sometimes sends 389691382139 ??
            "https://example.com": ("482839044422",),  # only this has popped up so far
            "http://facebook.com": (
                "10151063484068358",
                "405613579725",
                "411149314032",
            ),  # ?id=http%3A%2F%2Ffacebook.com
            "https://facebook.com": (
                "10151063484068358",
                "405613579725",
                "411149314032",
            ),  # facebook graph has a bug where the wrong object is returned FOR FACEBOOK.com
        }
        hub = self._newHub()

        get_data = {
            "ids": ",".join([quote_plus(i) for i in urls.keys()]),
            "fields": "id,og_object",
        }

        fb_data = hub.api_proxy(
            url="https://graph.facebook.com",
            expected_format="json.load",
            get_data=get_data,
        )
        if GO_SLOWLY:
            time.sleep(1)
        for url in urls.keys():
            self.assertIn(url, fb_data)
            self.assertIn("og_object", fb_data[url])
            self.assertIn("id", fb_data[url]["og_object"])
            self.assertIn(
                fb_data[url]["og_object"]["id"], urls[url]
            )  # test the opengraph id against many potentials


# ==============================================================================


class TestFacebookUtils_Authenticated_NoVersion(
    _TestFacebookUtils_Authenticated_Core, unittest.TestCase
):
    fb_api_version = None


class TestFacebookUtils_Authenticated_16_0(
    _TestFacebookUtils_Authenticated_Core, unittest.TestCase
):
    fb_api_version = "16.0"


class TestFacebookUtils_Authenticated_17_0(
    _TestFacebookUtils_Authenticated_Core, unittest.TestCase
):
    fb_api_version = "17.0"


class TestFacebookUtils_Authenticated_18_0(
    _TestFacebookUtils_Authenticated_Core, unittest.TestCase
):
    fb_api_version = "18.0"


class TestFacebookUtils_Authenticated_19_0(
    _TestFacebookUtils_Authenticated_Core, unittest.TestCase
):
    fb_api_version = "19.0"


class TestFacebookUtils_Authenticated_20_0(
    _TestFacebookUtils_Authenticated_Core, unittest.TestCase
):
    fb_api_version = "20.0"


class TestFacebookUtils_Authenticated_21_0(
    _TestFacebookUtils_Authenticated_Core, unittest.TestCase
):
    fb_api_version = "21.0"


class TestFacebookUtils_Authenticated_22_0(
    _TestFacebookUtils_Authenticated_Core, unittest.TestCase
):
    fb_api_version = "22.0"


class TestFacebookUtils_Authenticated_23_0(
    _TestFacebookUtils_Authenticated_Core, unittest.TestCase
):
    fb_api_version = "23.0"


# test Unaauthenticated


class TestFacebookUtils_UnAuthenticated_NoVersion(
    _TestFacebookUtils_UnAuthenticated, unittest.TestCase
):
    fb_api_version = None


class TestFacebookUtils_UnAuthenticated_16_0(
    _TestFacebookUtils_UnAuthenticated, unittest.TestCase
):
    fb_api_version = "16.0"


class TestFacebookUtils_UnAuthenticated_17_0(
    _TestFacebookUtils_UnAuthenticated, unittest.TestCase
):
    fb_api_version = "17.0"


class TestFacebookUtils_UnAuthenticated_18_0(
    _TestFacebookUtils_UnAuthenticated, unittest.TestCase
):
    fb_api_version = "18.0"


class TestFacebookUtils_UnAuthenticated_19_0(
    _TestFacebookUtils_UnAuthenticated, unittest.TestCase
):
    fb_api_version = "19.0"


class TestFacebookUtils_UnAuthenticated_20_0(
    _TestFacebookUtils_UnAuthenticated, unittest.TestCase
):
    fb_api_version = "20.0"


class TestFacebookUtils_UnAuthenticated_21_0(
    _TestFacebookUtils_UnAuthenticated, unittest.TestCase
):
    fb_api_version = "21.0"


class TestFacebookUtils_UnAuthenticated_22_0(
    _TestFacebookUtils_UnAuthenticated, unittest.TestCase
):
    fb_api_version = "22.0"


class TestFacebookUtils_UnAuthenticated_23_0(
    _TestFacebookUtils_UnAuthenticated, unittest.TestCase
):
    fb_api_version = "23.0"
