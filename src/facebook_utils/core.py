# -*- coding: utf-8 -*-
import base64
from functools import wraps
import hashlib
import hmac
import json
import logging
import time
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import overload
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

# pypi
import requests
from typing_extensions import Literal

# local
from .api_urls import FacebookApiUrls
from .api_urls import FB_URL_GRAPH_API
from .api_urls import FB_URL_WEB
from .exceptions import (
    ApiApplicationError,
    ApiAuthError,
    ApiAuthExpiredError,
    ApiError,
    ApiRatelimitedError,
    ApiResponseError,
    ApiRuntimeGrantError,
    ApiRuntimeGraphMethodError,
    ApiRuntimeScopeError,
    ApiRuntimeVerirficationFormatError,
    ApiUnhandledError,
    AuthenticatedHubRequired,
)
from .exceptions import reformat_error
from .utils import parse_environ
from .utils import RE_api_version_fixable
from .utils import RE_api_version_valid
from .utils import warn_future

if TYPE_CHECKING:
    import pyramid.request
    from requests import Response

# ==============================================================================


log = logging.getLogger(__name__)

# PORT
_fbutils_env = parse_environ()
DEBUG = _fbutils_env["debug"]
FB_API_VERSION = _fbutils_env["fb_api_version"]


# ------------------------------------------------------------------------------


def extract__code_from_redirect(url: str) -> str:
    _parsed = urlparse(url)
    _parsed_qs = parse_qs(_parsed.query)
    assert "code" in _parsed_qs
    assert len(_parsed_qs["code"]) == 1
    _code = _parsed_qs["code"][0]
    return _code


def require_authenticated_hub(f: Callable) -> Callable:
    """simple decorator for FacebookHub class methods."""

    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if self.unauthenticated_hub:
            raise AuthenticatedHubRequired()
        return f(self, *args, **kwargs)

    return wrapper


class FacebookHub(object):
    app_id: Optional[str] = None
    app_secret: Optional[str] = None
    # https://developers.facebook.com/docs/facebook-login/security/#proof
    # The app secret proof is a sha256 hash of your access token,
    # using your app secret as the key.
    enable_secretproof: bool = True
    app_scope: Optional[str] = None
    app_domain: Optional[str] = None
    fb_api_version: Optional[float] = None
    oauth_code_redirect_uri: Optional[str] = None
    oauth_token_redirect_uri: Optional[str] = None
    debug_error: bool = False
    mask_unhandled_exceptions: bool = False
    ssl_verify: bool = True
    secure_only: bool = True
    unauthenticated_hub: bool = False
    callback_ratelimited: Optional[Callable] = None

    # these will be urls, preferably versioned
    fb_url_graph_api: str
    fb_url_web: str

    # stash for debugging
    _last_response: Optional[requests.Response] = None
    _penultimate_response: Optional[requests.Response] = None

    def __init__(
        self,
        mask_unhandled_exceptions: bool = False,
        oauth_token_redirect_uri: Optional[str] = None,
        oauth_code_redirect_uri: Optional[str] = None,
        fb_api_version: Optional[str] = None,  # parsed to float
        debug_error: bool = False,
        app_domain: Optional[str] = None,
        app_secret: Optional[str] = None,
        enable_secretproof: bool = True,
        ssl_verify: bool = True,
        secure_only: bool = True,
        app_scope: Optional[str] = None,
        app_id: Optional[str] = None,
        unauthenticated_hub: Optional[bool] = None,
        callback_ratelimited: Optional[Callable[["Response"], None]] = None,
    ):
        """
        Initialize the ``FacebookHub`` object with some variables.

        required kwargs:
            `app_id`
            `app_secret`

            or
            `unauthenticated_hub=True`

        callback_ratelimited:
            callable that accepts the `request.Response` object and returns nothing.
            It will be called before raising the API RateLimited::

                def callback_ratelimited(response: "Response")->None:
                    global APP_RATELIMITED
                    APP_RATELIMITED = True
        """
        if unauthenticated_hub is True:
            self.unauthenticated_hub = True
        else:
            if app_id is None or app_secret is None:
                raise ValueError(
                    "Must initialize FacebookHub() with an app_id and an app_secret"
                )

        # this seems assbackwards, but we want to store a numeric version of the facebook api version
        _fb_api_version = fb_api_version or FB_API_VERSION
        if _fb_api_version:
            if TYPE_CHECKING:
                assert isinstance(_fb_api_version, str)
            if RE_api_version_valid.match(_fb_api_version):
                # ignore the initial v
                _fb_api_version = _fb_api_version[1:]
            else:
                if not RE_api_version_fixable.match(_fb_api_version):
                    raise ValueError("Invalid API version: %s" % _fb_api_version)
        self.fb_api_version = float(_fb_api_version) if _fb_api_version else None

        if _fb_api_version is None:
            self.fb_url_graph_api = FB_URL_GRAPH_API
        else:
            # insert the v here
            self.fb_url_graph_api = ("{fb_url_graph_api}/v{version}").format(
                fb_url_graph_api=FB_URL_GRAPH_API, version=self.fb_api_version
            )
        self.fb_url_web = FB_URL_WEB
        self.mask_unhandled_exceptions = mask_unhandled_exceptions
        self.oauth_token_redirect_uri = oauth_token_redirect_uri
        self.oauth_code_redirect_uri = oauth_code_redirect_uri
        self.debug_error = debug_error
        self.app_secret = app_secret
        self.enable_secretproof = enable_secretproof
        self.app_domain = app_domain
        self.ssl_verify = ssl_verify
        self.secure_only = secure_only
        self.app_scope = app_scope
        self.app_id = app_id
        self.callback_ratelimited = callback_ratelimited

    def extract__code_from_redirect(self, url: str) -> str:
        return extract__code_from_redirect(url)

    @require_authenticated_hub
    def oauth_code__url_dialog(
        self,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        auth_type: Optional[str] = None,
    ):
        """
        Generates the URL for an oAuth dialog to Facebook for a "code" flow.
        This flow will return the user to your website with a 'code' object in a query param.

        Note on `auth_type`
        Facebook's API requires `auth_type=rerequest` for re-requested attributes
        via https://developers.facebook.com/docs/facebook-login/permissions/v2.5#adding
            "If someone has declined a permission for your app, the login dialog won't let your app re-request the permission unless you pass auth_type=rerequest along with your request."
        """
        if scope is None:
            scope = self.app_scope
        if redirect_uri is None:
            redirect_uri = self.oauth_code_redirect_uri
        if TYPE_CHECKING:
            assert self.app_id is not None
            assert redirect_uri is not None
            assert scope is not None
            assert auth_type is not None
        return FacebookApiUrls.oauth_code__url_dialog(
            fb_url_web=self.fb_url_web,
            app_id=self.app_id,
            redirect_uri=redirect_uri,
            scope=scope,
            auth_type=auth_type,
        )

    @require_authenticated_hub
    def oauth_code__url_access_token(
        self,
        submitted_code: str,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
    ):
        """
        Generates the URL to grab an access token from Facebook.
        This is returned based on EXACTLY matching the app_id, app_secret,
        and 'code' with the redirect_uri.
        If you change the redirect uri - or any other component - it will break.
        https://graph.facebook.com/oauth/access_token?client_id=YOUR_APP_ID&redirect_uri=YOUR_URL&client_secret=YOUR_APP_SECRET&code=THE_CODE_FROM_URL_DIALOG_TOKEN
        """
        if submitted_code is None:
            raise ValueError(
                "`FacebookHub.oauth_code__url_access_token` MUST be invoked with `submitted_code`."
            )
        if redirect_uri is None:
            redirect_uri = self.oauth_code_redirect_uri
        if scope is None:
            scope = self.app_scope
        if self.app_secret is None:
            raise ValueError(
                "`FacebookHub.oauth_code__url_access_token` MUST be invoked with a configured `self.app_secret`."
            )
        if TYPE_CHECKING:
            assert self.app_id is not None
            assert redirect_uri is not None
        return FacebookApiUrls.oauth_code__url_access_token(
            fb_url_graph_api=self.fb_url_graph_api,
            app_id=self.app_id,
            redirect_uri=redirect_uri,
            app_secret=self.app_secret,
            submitted_code=submitted_code,
        )

    def last_response_ratelimited(self) -> Optional[Dict]:
        warn_future(
            """Deprecated `last_response_ratelimited()`; """
            """call `last_response_usage` property instead"""
        )
        return self.last_response_usage

    @property
    def last_response_usage(self) -> Optional[Dict]:
        """
        This property checks headers for `x-page-usage`, `x-app-usage`, x-ad-account-usage:

        This will return a reporting dict or none
        The reporting dict will have decoded of the headers, if possible, or be
        an empty dict

            reporting = {
                        # The values for x, y and z are whole numbers representing the percentage used values for each of the metrics. When any of these metrics exceed 100 the app is rate limited.
                        'X-Page-Usage': {"call_count":0,
                                          "total_cputime":0,
                                          "total_time":0
                                          }'
                        # The values for x, y and z are whole numbers representing the percentage used values for each of the metrics. When any of these metrics exceed 100 the app is rate limited.
                         'x-app-usage': {"call_count":0,
                                         "total_cputime":0,
                                         "total_time":0
                                         }'
                        ''
                         }
        """
        # a bad `Request` is an object that evaluates to None. grr.
        if self._last_response is not None:
            if self._last_response.headers:
                reporting = {}
                for _report in ("X-Page-Usage", "x-app-usage", "x-ad-account-usage"):
                    if _report in self._last_response.headers:
                        reporting[_report] = json.loads(
                            self._last_response.headers[_report]
                        )
                return reporting
        return None

    @property
    def last_response_is_ratelimited(self) -> bool:
        """
        checks for ratelimited response header
        """
        # a bad `Request` is an object that evaluates to None. grr.
        if self._last_response is not None:
            if self._last_response.headers:
                if "WWW-Authenticate" in self._last_response.headers:
                    if (
                        self._last_response.headers["WWW-Authenticate"]
                        == 'OAuth "Facebook Platform" "invalid_request" "(#4) Application request limit reached"'
                    ):
                        return True
        return False

    def generate__appsecret_proof(
        self,
        access_token: Optional[str] = None,
    ) -> Optional[str]:
        """
        https://developers.facebook.com/docs/graph-api/securing-requests
        """
        if not self.enable_secretproof:
            return None
        if access_token is None:
            return None
        if self.app_secret is None:
            raise ValueError(
                "`FacebookHub.generate__appsecret_proof` MUST be configured with `self.app_secret`."
            )
        h = hmac.new(
            self.app_secret.encode(),
            msg=access_token.encode(),
            digestmod=hashlib.sha256,
        )
        return h.hexdigest()

    @overload
    def api_proxy(  # noqa: E704
        self,
        url: Optional[str] = None,
        post_data: Optional[Dict] = None,
        expected_format: Literal["json.loads"] = "json.loads",
        is_delete: bool = False,
        ssl_verify: Optional[bool] = None,
        access_token: Optional[str] = None,
        get_data: Optional[Dict] = None,
    ) -> Dict[Any, Any]: ...

    @overload
    def api_proxy(  # noqa: E704
        self,
        url: Optional[str] = None,
        post_data: Optional[Dict] = None,
        expected_format: Literal["json.load"] = "json.load",
        is_delete: bool = False,
        ssl_verify: Optional[bool] = None,
        access_token: Optional[str] = None,
        get_data: Optional[Dict] = None,
    ) -> Dict[Any, Any]: ...

    def api_proxy(
        self,
        url: Optional[str] = None,
        post_data: Optional[Dict] = None,
        expected_format: Literal[
            "json.loads", "json.load", "urlparse.parse_qs"
        ] = "json.loads",
        is_delete: bool = False,
        ssl_verify: Optional[bool] = None,
        access_token: Optional[str] = None,
        get_data: Optional[Dict] = None,
    ) -> Union[List[Any], Dict[Any, Any]]:
        """
        General proxy access

        If using this directly, you probably want to pass in an "access_token" kwarg in `post_data`
        """
        response = None
        response_content = None
        if ssl_verify is None:
            ssl_verify = self.ssl_verify

        # stash the original url
        # _url_original = url

        # quickly
        if not url:
            # url = "%s/" % self.fb_url_graph_api
            if self.fb_url_graph_api is None:
                raise ValueError(
                    "`FacebookHub.api_proxy` MUST be configured with `self.fb_url_graph_api`."
                )
            url = self.fb_url_graph_api
        else:
            _url_compare = url.lower()
            if _url_compare[:7] == "http://":
                if self.secure_only:
                    raise ApiError(
                        "This API client is configured to only work on https endpoints"
                    )
            elif _url_compare[:8] == "https://":
                pass
            else:
                if _url_compare[0] == "/":
                    url = self.fb_url_graph_api + url
                else:
                    raise ApiError("Not sure what sort of endpoint you are thinking of")

        # add in an access token to URLs if needed.
        if access_token:
            if not get_data or not get_data.get("access_token"):
                if "access_token=" not in url:
                    _access_token = urlencode(dict(access_token=access_token))
                    if "?" not in url:
                        url += "?" + _access_token
                    else:
                        url += "&" + _access_token
        else:
            # derive the access token if possible from the url
            if post_data and "access_token" in post_data:
                access_token = post_data["access_token"]
            elif get_data and "access_token" in get_data:
                access_token = get_data["access_token"]
            elif "access_token=" in url:
                _parsed = urlparse(url)
                if _parsed.query:
                    _qs = parse_qs(_parsed.query)
                    _candidate = _qs.get(
                        "access_token"
                    )  # this will be `None` or a list
                    access_token = _candidate[0] if _candidate else None

        if self.enable_secretproof:
            if access_token:
                if "access_token=" in url:
                    if "appsecret_proof=" not in url:
                        _appsecret_proof = self.generate__appsecret_proof(
                            access_token=access_token
                        )
                        if not _appsecret_proof:
                            raise ValueError("Did not `generate__appsecret_proof()`")
                        url += "&appsecret_proof=" + _appsecret_proof
                elif get_data and "access_token" in get_data:
                    if "appsecret_proof" not in get_data:
                        _appsecret_proof = self.generate__appsecret_proof(
                            access_token=access_token
                        )
                        if _appsecret_proof:
                            get_data["appsecret_proof"] = _appsecret_proof
                elif post_data and "access_token" in post_data:
                    if "appsecret_proof" not in post_data:
                        _appsecret_proof = self.generate__appsecret_proof(
                            access_token=access_token
                        )
                        if _appsecret_proof:
                            post_data["appsecret_proof"] = _appsecret_proof

        try:
            if not post_data:
                # normal get
                response = requests.get(url, params=get_data, verify=ssl_verify)
            else:
                if post_data:
                    if "batch" in post_data:
                        if isinstance(post_data["batch"], list):
                            post_data["batch"] = json.dumps(post_data["batch"])
                if is_delete:
                    response = requests.delete(url, data=post_data, verify=ssl_verify)
                else:
                    response = requests.post(url, data=post_data, verify=ssl_verify)

            # store the response for possible later debugging by user
            # e.g. `response.headers['X-FB-Debug']`
            self._penultimate_response = self._last_response
            self._last_response = response

            # response.text is the decoded response
            # response.content is the raw response
            _response_content = response.text

            if response.status_code == 200:
                if expected_format in ("json.load", "json.loads"):
                    response_content = json.loads(_response_content)
                    if (
                        (post_data is not None)
                        and isinstance(post_data, dict)
                        and ("batch" in post_data)
                    ):
                        if not isinstance(response_content, list):
                            raise ApiResponseError(
                                message="Batched Graph request expects a list of dicts. Did not get a list.",
                                response=response_content,
                            )
                        for li in response_content:
                            if not isinstance(li, dict):
                                raise ApiResponseError(
                                    message="Batched Graph request expects a list of dicts. Got a list, element not a dict.",
                                    response=response_content,
                                )
                            if not all(k in li for k in ("body", "headers", "code")):
                                raise ApiResponseError(
                                    message="Batched Graph response dict should contain 'body', 'headers', 'code'.",
                                    response=response_content,
                                )
                            # the body is a json encoded string itself.  it was previously escaped, so unescape it!
                            li["body"] = json.loads(li["body"])

                elif expected_format == "urlparse.parse_qs":
                    response_content = parse_qs(_response_content)
                else:
                    raise ValueError("Unexpected Format: %s" % expected_format)
            else:
                if DEBUG:
                    print(response)
                    print(response.__dict__)
                if response.status_code == 400:
                    rval = ""
                    try:
                        rval = json.loads(_response_content)
                        if "error" in rval:
                            error = reformat_error(rval["error"])
                            if ("code" in error) and error["code"]:
                                if error["code"] == 1:
                                    # Error validating client secret
                                    raise ApiApplicationError(**error)
                                elif error["code"] == 101:
                                    # Error validating application. Invalid application ID
                                    raise ApiApplicationError(**error)
                                elif error["code"] == 100:
                                    if ("type" in error) and error["type"]:
                                        if error["type"] == "GraphMethodException":
                                            raise ApiRuntimeGraphMethodError(**error)
                                    if ("message" in error) and error["message"]:
                                        if (
                                            error["message"][:32]
                                            == "Invalid verification code format"
                                        ):
                                            raise ApiRuntimeVerirficationFormatError(
                                                **error
                                            )
                                        elif (
                                            error["message"][:19]
                                            == "Invalid grant_type:"
                                        ):
                                            raise ApiRuntimeGrantError(**error)
                                        elif (
                                            error["message"][:18]
                                            == "Unsupported scope:"
                                        ):
                                            raise ApiRuntimeScopeError(**error)
                                        elif (
                                            error["message"][:18]
                                            == "Unsupported scope:"
                                        ):
                                            raise ApiRuntimeScopeError(**error)

                                elif error["code"] == 104:
                                    raise ApiAuthError(**error)

                            if ("message" in error) and error["message"]:
                                if (
                                    error["message"][:63]
                                    == "Error validating access token: Session has expired at unix time"
                                ):
                                    raise ApiAuthExpiredError(**error)
                                elif (
                                    "The access token is invalid since the user hasn't engaged the app in longer than 90 days."
                                    in error["message"]
                                ):
                                    raise ApiAuthExpiredError(**error)
                                elif (
                                    error["message"][:26]
                                    == "Invalid OAuth access token"
                                ):
                                    raise ApiAuthError(**error)
                                elif (
                                    error["message"][:29]
                                    == "Error validating access token"
                                ):
                                    raise ApiAuthError(**error)
                            if ("type" in error) and (
                                error["type"] == "OAuthException"
                            ):
                                if DEBUG:
                                    print("#=" * 80)
                                    print("api_proxy")
                                    print("error", error)
                                    print("get_data", get_data)
                                    print("post_data", post_data)
                                    # print("url", url)
                                    # print("self", pprint.pformat(self.__dict__))
                                    print(
                                        "access_token", True if access_token else False
                                    )
                                    print(
                                        "FBUTILS_DEBUG_SECRET",
                                        _fbutils_env["debug_secret"],
                                    )
                                    print("#=" * 80)
                                raise ApiAuthError(**error)
                            raise ApiError(**error)
                        raise ApiError(
                            message="I don't know how to handle this error (%s)" % rval,
                            code=400,
                        )
                    except json.JSONDecodeError as exc:
                        raise ApiError(
                            message="Could not parse JSON from the error (%s)" % rval,
                            code=400,
                            raised=exc,
                        )
                    except Exception:
                        raise
                if self.last_response_is_ratelimited:
                    if self.callback_ratelimited is not None:
                        self.callback_ratelimited(response)
                    raise ApiRatelimitedError(
                        message="Application is ratelimited. %s"
                        % self.last_response_usage,
                        code=response.status_code,
                    )
                raise ApiError(
                    message="Could not communicate with the API",
                    code=response.status_code,
                )
            return response_content
        except json.JSONDecodeError as exc:
            raise ApiError(
                message="Could not parse JSON from the error (%s)" % exc, raised=exc
            )
        except Exception as exc:
            if self.mask_unhandled_exceptions:
                if not isinstance(exc, ApiError):
                    raise ApiUnhandledError(raised=exc)
            raise

    @require_authenticated_hub
    def oauth_code__get_access_token(
        self,
        submitted_code: str,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        keep_response: bool = False,
    ) -> Union[str, Tuple[str, Dict]]:
        """
        Gets the access token from Facebook that corresponds with a code.
        This uses `requests` to open the url, so should be considered as blocking code.
        If `keep_response` is set, will return a tuple of `access_token` and the response
        """
        if submitted_code is None:
            raise ValueError(
                "`FacebookHub.oauth_code__get_access_token` MUST be invoked with `submitted_code`."
            )
        if scope is None:
            scope = self.app_scope
        if redirect_uri is None:
            redirect_uri = self.oauth_code_redirect_uri
        url_access_token = self.oauth_code__url_access_token(
            submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope
        )
        try:
            response = self.api_proxy(url_access_token, expected_format="json.loads")
            if "access_token" not in response:
                raise ApiError(message="invalid response")
            access_token = response["access_token"]
            if keep_response:
                return access_token, response
            return access_token
        except Exception:
            raise

    @require_authenticated_hub
    def oauth_code__get_access_token_and_profile(
        self,
        submitted_code: str,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> Tuple[str, Dict]:
        """
        Gets the access token AND a profile from Facebook that corresponds with a code.
        This method wraps a call to `oauth_code__get_access_token`, then wraps `graph__get_profile_for_access_token` which opens a json object at the url returned by `graph__url_me_for_access_token`.
        This is a convenience method, since most people want to do that (at least on the initial Facebook auth.
        This wraps methods which use `requests` to open urls, so should be considered as blocking code.
        """
        if submitted_code is None:
            raise ValueError(
                "`FacebookHub.oauth_code__get_access_token_and_profile` MUST be invoked with `submitted_code`."
            )
        (access_token, profile) = (None, None)
        try:
            access_token = self.oauth_code__get_access_token(
                submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope
            )
            profile = self.graph__get_profile_for_access_token(
                access_token=access_token, fields=fields
            )
        except Exception:
            raise
        return (access_token, profile)

    @require_authenticated_hub
    def oauth_token__url_dialog(
        self,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        auth_type: Optional[str] = None,
    ) -> str:
        """
        Generates the URL for an oAuth dialog to Facebook.
        This flow will return the user to your website with a 'token' object as a URI hashstring.
        This hashstring can not be seen by the server, it must be handled via javascript.

        Note on `auth_type`
        Facebook's API requires `auth_type=rerequest` for re-requested attributes
        via https://developers.facebook.com/docs/facebook-login/permissions/v2.5#adding
            "If someone has declined a permission for your app, the login dialog won't let your app re-request the permission unless you pass auth_type=rerequest along with your request."
        """
        if redirect_uri is None:
            redirect_uri = self.oauth_token_redirect_uri
            if redirect_uri is None:
                raise ValueError(
                    "`FacebookHub.oauth_token__url_dialog` MUST be invoked with `redirect_uri` or configured with `oauth_token_redirect_uri`."
                )
        if scope is None:
            scope = self.app_scope
            if scope is None:
                raise ValueError(
                    "`FacebookHub.oauth_token__url_dialog` MUST be invoked with `scope` or configured with `app_scope`."
                )
        if auth_type is None:
            raise ValueError(
                "`FacebookHub.oauth_token__url_dialog` MUST be invoked with `auth_type`."
            )
        if self.app_id is None:
            raise ValueError(
                "`FacebookHub.oauth_token__url_dialog` MUST be configured with `self.app_id`."
            )
        return FacebookApiUrls.oauth_token__url_dialog(
            fb_url_web=self.fb_url_web,
            app_id=self.app_id,
            redirect_uri=redirect_uri,
            scope=scope,
            auth_type=auth_type,
        )

    @require_authenticated_hub
    def oauth__url_extend_access_token(
        self,
        access_token: str,
    ) -> str:
        """
        Generates the URL to extend an access token from Facebook.

        see https://developers.facebook.com/roadmap/offline-access-removal/

        https://graph.facebook.com/oauth/access_token?
            client_id=APP_ID&
            app_secret=APP_SECRET&
            grant_type=fb_exchange_token&
            fb_exchange_token=EXISTING_ACCESS_TOKEN

        oddly, this returns a url formatted string and not a json document.  go figure.

        """
        if not access_token:
            raise ValueError(
                "`FacebookHub.oauth__url_extend_access_token` MUST be invoked with `access_token`."
            )
        if self.app_id is None:
            raise ValueError(
                "`FacebookHub.oauth__url_extend_access_token` MUST be configured with `self.app_id`."
            )
        if self.app_secret is None:
            raise ValueError(
                "`FacebookHub.oauth__url_extend_access_token` MUST be configured with `self.app_id`."
            )
        return FacebookApiUrls.oauth__url_extend_access_token(
            fb_url_graph_api=self.fb_url_graph_api,
            app_id=self.app_id,
            app_secret=self.app_secret,
            access_token=access_token,
        )

    @require_authenticated_hub
    def graph__extend_access_token(
        self,
        access_token: str,
    ) -> Dict:
        """
        see `oauth__url_extend_access_token`
        """
        if not access_token:
            raise ValueError("must submit access_token")
        try:
            url = self.oauth__url_extend_access_token(access_token=access_token)
            response = self.api_proxy(url, expected_format="json.load")
        except Exception:
            raise
        return response

    @require_authenticated_hub
    def graph__url_me(
        self,
        access_token: str,
    ) -> None:
        raise ValueError("Deprecated; call graph__url_me_for_access_token instead")

    @require_authenticated_hub
    def graph__url_me_for_access_token(
        self,
        access_token: str,
        fields: Optional[str] = None,
    ) -> str:
        if not access_token:
            raise ValueError(
                "`FacebookHub.graph__url_me_for_access_token` MUST be invoked with `access_token`."
            )
        if fields is None:
            fields = self.app_scope

        return FacebookApiUrls.graph__url_me_for_access_token(
            fb_url_graph_api=self.fb_url_graph_api,
            access_token=access_token,
            fields=fields,
            app_secretproof=self.generate__appsecret_proof(access_token),
        )

    @require_authenticated_hub
    def graph__url_user_for_access_token(
        self,
        access_token: str,
        user: str,
        action: str,
        fields: str,
    ) -> str:
        if not access_token:
            raise ValueError(
                "`FacebookHub.graph__url_user_for_access_token` MUST be invoked with `access_token`."
            )
        if not user:
            raise ValueError(
                "`FacebookHub.graph__url_user_for_access_token` MUST be invoked with `user`."
            )
        return FacebookApiUrls.graph__url_user_for_access_token(
            fb_url_graph_api=self.fb_url_graph_api,
            access_token=access_token,
            user=user,
            action=action,
            fields=fields,
            app_secretproof=self.generate__appsecret_proof(access_token),
        )

    @require_authenticated_hub
    def graph__get_profile_for_access_token(
        self,
        access_token: str,
        user: Optional[str] = None,
        action: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> Dict:
        """
        Grabs a profile for a user, corresponding to a profile, from Facebook.
        This uses `requests` to open the url, so should be considered as blocking code.
        """
        if not access_token:
            raise ValueError(
                "`FacebookHub.graph__get_profile_for_access_token` MUST be invoked with `access_token`."
            )
        profile = None
        try:
            url = None
            if not user:
                if action:
                    url = self.graph__url_user_for_access_token(
                        access_token, action=action, fields=fields
                    )
                else:
                    url = self.graph__url_me_for_access_token(
                        access_token, fields=fields
                    )
            else:
                url = self.graph__url_user_for_access_token(
                    access_token, user=user, action=action, fields=fields
                )
            profile = self.api_proxy(url, expected_format="json.load")
        except Exception:
            raise
        return profile

    @require_authenticated_hub
    def graph__get_profile(self, access_token: str) -> None:
        raise ValueError("Deprecated; call graph__get_profile_for_access_token instead")

    @require_authenticated_hub
    def graph__action_create(
        self,
        access_token: str,
        fb_app_namespace: str,
        fb_action_type_name: str,
        object_type_name: str,
        object_instance_url: str,
    ) -> Dict:
        if not all((access_token, fb_app_namespace, fb_action_type_name)):
            raise ValueError(
                "must submit access_token, fb_app_namespace, fb_action_type_name"
            )
        if not all((object_type_name, object_instance_url)):
            raise ValueError("must submit object_type_name, object_instance_url")

        url = FacebookApiUrls.graph__action_create_url(
            fb_url_graph_api=self.fb_url_graph_api,
            fb_app_namespace=fb_app_namespace,
            fb_action_type_name=fb_action_type_name,
        )
        post_data: Dict[str, str] = {
            "access_token": access_token,
            object_type_name: object_instance_url,
        }
        if self.enable_secretproof:
            appsecret_proof = self.generate__appsecret_proof(access_token)
            if TYPE_CHECKING:
                assert appsecret_proof
            post_data["appsecret_proof"] = appsecret_proof
        try:
            payload = self.api_proxy(url, post_data, expected_format="json.load")
            return payload
        except Exception:
            raise

    @require_authenticated_hub
    def graph__action_list(
        self,
        access_token: str,
        fb_app_namespace: str,
        fb_action_type_name: str,
    ) -> Dict:
        if not all((access_token, fb_app_namespace, fb_action_type_name)):
            raise ValueError(
                "must submit access_token, fb_app_namespace, fb_action_type_name"
            )

        url = FacebookApiUrls.graph__action_list_url(
            fb_url_graph_api=self.fb_url_graph_api,
            fb_app_namespace=fb_app_namespace,
            fb_action_type_name=fb_action_type_name,
            access_token=access_token,
        )
        try:
            payload = self.api_proxy(url, expected_format="json.load")
            return payload
        except Exception:
            raise

    @require_authenticated_hub
    def graph__action_delete(
        self,
        access_token: str,
        action_id: str,
    ) -> Dict:
        if not all((access_token, action_id)):
            raise ValueError("must submit action_id")

        url = FacebookApiUrls.graph__action_delete_url(
            fb_url_graph_api=self.fb_url_graph_api, action_id=action_id
        )
        post_data = {"access_token": access_token}
        if self.enable_secretproof:
            appsecret_proof = self.generate__appsecret_proof(access_token)
            if TYPE_CHECKING:
                assert appsecret_proof
            post_data["appsecret_proof"] = appsecret_proof
        try:
            payload = self.api_proxy(
                url, post_data=post_data, expected_format="json.load", is_delete=True
            )
            return payload
        except Exception:
            raise

    @require_authenticated_hub
    def verify_signed_request(
        self,
        signed_request: str,
        timeout: Optional[int] = None,
    ) -> Tuple[bool, Dict]:
        """
        Removed in v0.6.0; will raise a `NotImplementedError`

        Removal Information:

            I am unsure if Facebook actually still supports this. It used to be
            a component of multiple Facebook API Products and Operations, but
            now seems to be unused and largely undocumented.

            The nested function `base64_url_decode` does not work on Python3.
            There are likely newer and better ways to implement this, but I can
            not find a way to make any Facebook API generate this type of
            signature to test against.

            For those reasons, the code remains below for legacy information and
            to potentially revive, but the function will immediately raise
            a `NotImplementedError`.

            It I learn of a way to trigger and test this response, it will likely
            return.


        verifies the signedRequest from Facebook.
        accepts a `timeout` value as a kwarg, to test against the 'issued_at' key within the payload

        This will always return a Tuple of (BOOL, DICT)

        Bool:
            True = Signed Request is verified
            False = Signed Request is not verified

        Dict:
            if request is verified: the payload object as JSON
            if request is not verified: a 'python-error' key with the reason

        PLEASE NOTE:
            1. if the request is verified, but the data is outside of the timeout, this will return FALSE as a bool; and the dict will the verified payload with an 'python-error' key.
            2. i chose 'python-error', because Facebook is likely to change their spec. they do that. the chances of them adding 'error' are much greater than 'python-error'

        Reference documentation
        https://developers.facebook.com/docs/authentication/signed_request/
        "The signed_request parameter is the concatenation of a HMAC SHA-256 signature string, a period (.), and a base64url encoded JSON object."

        after starting this, i found someone already did the hard work.
        following is based on Sunil Arora's blog post - http://sunilarora.org/parsing-signedrequest-parameter-in-python-bas
        """
        # raise NotImplementedError("`verify_signed_request` was removed in v0.6.0")

        # code below is broken

        if signed_request is None:
            raise ValueError("must submit signed_request")
        if self.app_secret is None:
            raise ValueError(
                "`FacebookHub.verify_signed_request` MUST be configured with `app_secret`."
            )

        def base64_url_decode(inp: str) -> bytes:
            # TODO: this is probably broken
            # but it's also unused and unstestable!
            padding_factor = (4 - len(inp) % 4) % 4
            inp += "=" * padding_factor
            return base64.b64decode(
                inp.translate(dict(list(zip(list(map(ord, "-_"), "+/")))))  # type: ignore[arg-type,call-overload]
            )

        (signature, payload) = signed_request.split(".")
        decoded_signature = base64_url_decode(signature)
        data = json.loads(base64_url_decode(payload))

        if data.get("algorithm").upper() != "HMAC-SHA256":
            return (
                False,
                {
                    "python-error": "Unknown algorithm - %s"
                    % data.get("algorithm").upper()
                },
            )

        expected_sig = hmac.new(
            self.app_secret.encode(),
            msg=payload.encode(),
            digestmod=hashlib.sha256,
        ).digest()

        if decoded_signature != expected_sig:
            return (
                False,
                {
                    "python-error": "signature (%s) != expected_sig (%s)"
                    % (decoded_signature.decode(), expected_sig.decode())
                },
            )

        if timeout:
            time_now = int(time.time())
            diff = time_now - data["issued_at"]
            if diff > timeout:
                data["python-error"] = "payload issued outside of timeout window"
                return (False, data)

        return (True, data)


class FacebookPyramid(FacebookHub):
    request: "pyramid.request.Request"

    def __init__(
        self,
        request: "pyramid.request.Request",
        oauth_token_redirect_uri: Optional[str] = None,
        oauth_code_redirect_uri: Optional[str] = None,
        fb_api_version: Optional[str] = None,
        app_secret: Optional[str] = None,
        enable_secretproof: Optional[bool] = None,  # None will pull rom
        app_domain: Optional[str] = None,
        ssl_verify: bool = True,
        secure_only: Optional[bool] = None,
        app_scope: Optional[str] = None,
        app_id: Optional[str] = None,
    ):
        """
        Creates a new ``FacebookHub`` object, sets it up with Pyramid Config vars, and then proxies other functions into it.
        """
        self.request = request
        registry_settings = request.registry.settings

        fb_utils_prefix = registry_settings.get("fbutils.prefix", "fbutils")

        _fb_api_version = fb_api_version or FB_API_VERSION
        if _fb_api_version is None:
            _fb_api_version = registry_settings.get(
                "%s.api_version" % fb_utils_prefix, None
            )
        if TYPE_CHECKING:
            assert isinstance(_fb_api_version, str) or (_fb_api_version is None)

        if app_id is None:
            app_id = registry_settings.get("%s.id" % fb_utils_prefix, None)
        if app_secret is None:
            app_secret = registry_settings.get("%s.secret" % fb_utils_prefix, None)
        if enable_secretproof is None:
            enable_secretproof = registry_settings.get(
                "%s.enable_secretproof" % fb_utils_prefix, None
            )
        if app_scope is None:
            app_scope = registry_settings.get("%s.scope" % fb_utils_prefix, None)
        if app_domain is None:
            app_domain = registry_settings.get("%s.domain" % fb_utils_prefix, None)
        if oauth_code_redirect_uri is None:
            oauth_code_redirect_uri = registry_settings.get(
                "%s.oauth_code_redirect_uri" % fb_utils_prefix, None
            )
        if oauth_token_redirect_uri is None:
            oauth_token_redirect_uri = registry_settings.get(
                "%s.oauth_token_redirect_uri" % fb_utils_prefix, None
            )
        if ssl_verify is None:
            ssl_verify = registry_settings.get("%s.ssl_verify" % fb_utils_prefix, True)
        if secure_only is None:
            secure_only = registry_settings.get(
                "%s.secure_only" % fb_utils_prefix, True
            )

        FacebookHub.__init__(
            self,
            app_id=app_id,
            app_secret=app_secret,
            enable_secretproof=enable_secretproof,
            app_scope=app_scope,
            app_domain=app_domain,
            oauth_code_redirect_uri=oauth_code_redirect_uri,
            oauth_token_redirect_uri=oauth_token_redirect_uri,
            ssl_verify=ssl_verify,
            secure_only=secure_only,
            fb_api_version=_fb_api_version,
        )

    @require_authenticated_hub
    def oauth_code__url_access_token(
        self,
        submitted_code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> str:
        if submitted_code is None:
            submitted_code = self.request.params.get("code", "MISSING")
        return FacebookHub.oauth_code__url_access_token(
            self, submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope
        )

    @require_authenticated_hub
    def oauth_code__get_access_token(
        self,
        submitted_code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> str:
        if submitted_code is None:
            submitted_code = self.request.params.get("code", "MISSING")
        return FacebookHub.oauth_code__get_access_token(
            self, submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope
        )

    @require_authenticated_hub
    def oauth_code__get_access_token_and_profile(
        self,
        submitted_code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> str:
        if submitted_code is None:
            submitted_code = self.request.params.get("code", "MISSING")
        return FacebookHub.oauth_code__get_access_token_and_profile(
            self,
            submitted_code=submitted_code,
            redirect_uri=redirect_uri,
            scope=scope,
            fields=fields,
        )
