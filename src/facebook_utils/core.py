# -*- coding: utf-8 -*-

# stdlib
import base64
import binascii
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
from typing import Tuple
from typing import Union
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

# pypi
import requests
from requests import Response

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


# ==============================================================================


log = logging.getLogger(__name__)

# PORT
_fbutils_env = parse_environ()
DEBUG = _fbutils_env["debug"]
FB_API_VERSION = _fbutils_env["fb_api_version"]


# ------------------------------------------------------------------------------


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
    app_secretproof: Optional[str] = None
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

    # these will be urls, preferably versioned
    fb_url_graph_api: str
    fb_url_web: str

    # stash for debugging
    _last_response: Optional[Response] = None
    _penultimate_response: Optional[Response] = None

    def __init__(
        self,
        mask_unhandled_exceptions: bool = False,
        oauth_token_redirect_uri: Optional[str] = None,
        oauth_code_redirect_uri: Optional[str] = None,
        fb_api_version: Optional[str] = None,
        debug_error: bool = False,
        app_domain: Optional[str] = None,
        app_secret: Optional[str] = None,
        app_secretproof: Optional[str] = None,
        ssl_verify: bool = True,
        secure_only: bool = True,
        app_scope: Optional[str] = None,
        app_id: Optional[str] = None,
        unauthenticated_hub: Optional[bool] = None,
    ):
        """
        Initialize the ``FacebookHub`` object with some variables.

        required kwargs:
            `app_id`
            `app_secret`

            or
            `unauthenticated_hub=True`
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
            if RE_api_version_valid.match(_fb_api_version):
                # ignore the initial v
                _fb_api_version = _fb_api_version[1:]
            else:
                if not RE_api_version_fixable.match(_fb_api_version):
                    raise ValueError("Invalid API version")
        self.fb_api_version = float(_fb_api_version) if _fb_api_version else None

        if _fb_api_version is None:
            self.fb_url_graph_api = FB_URL_GRAPH_API
        else:
            # insert the v here
            self.fb_url_graph_api = str("{fb_url_graph_api}/v{version}").format(
                fb_url_graph_api=FB_URL_GRAPH_API, version=self.fb_api_version
            )
        self.fb_url_web = FB_URL_WEB
        self.mask_unhandled_exceptions = mask_unhandled_exceptions
        self.oauth_token_redirect_uri = oauth_token_redirect_uri
        self.oauth_code_redirect_uri = oauth_code_redirect_uri
        self.debug_error = debug_error
        self.app_secret = app_secret
        self.app_secretproof = app_secretproof
        self.app_domain = app_domain
        self.ssl_verify = ssl_verify
        self.secure_only = secure_only
        self.app_scope = app_scope
        self.app_id = app_id

    @require_authenticated_hub
    def oauth_code__url_dialog(
        self,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        auth_type: Optional[str] = None,
    ) -> str:
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
        submitted_code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> str:
        """
        Generates the URL to grab an access token from Facebook.
        This is returned based on EXACTLY matching the app_id, app_secret, and 'code' with the redirect_uri.
        If you change the redirect uri - or any other component - it will break.
        https://graph.facebook.com/oauth/access_token?client_id=YOUR_APP_ID&redirect_uri=YOUR_URL&client_secret=YOUR_APP_SECRET&code=THE_CODE_FROM_URL_DIALOG_TOKEN
        """
        if submitted_code is None:
            raise ValueError("must call with submitted_code")
        if redirect_uri is None:
            redirect_uri = self.oauth_code_redirect_uri
        if scope is None:
            scope = self.app_scope
        return FacebookApiUrls.oauth_code__url_access_token(
            fb_url_graph_api=self.fb_url_graph_api,
            app_id=self.app_id,
            redirect_uri=redirect_uri,
            app_secret=self.app_secret,
            submitted_code=submitted_code,
        )

    def last_response_ratelimited(self) -> Optional[Dict]:
        warn_future(
            """Deprecated `last_response_ratelimited()`; call `last_response_usage` property instead"""
        )
        return self.last_response_usage

    @property
    def last_response_usage(self) -> Optional[Dict]:
        """
        This property checks headers for `x-page-usage`, `x-app-usage`, x-ad-account-usage:

        This will return a reporting dict or none
        The reporting dict will have decoded of the headers, if possible, or be an empty dict

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
        access_token: str,
    ) -> str:
        """
        https://developers.facebook.com/docs/graph-api/securing-requests
        """
        if not self.app_secret:
            raise ValueError("`must configure FacebookHub with a `app_secret`")
        if not self.app_secretproof:
            raise ValueError("`must configure FacebookHub with a `app_secretproof`")
        if access_token is None:
            raise ValueError("`must submit `access_token`")
        # PY3 requires bytes so `encode()`; this is PY2 compatible
        h = hmac.new(
            self.app_secret.encode(),
            msg=access_token.encode(),
            digestmod=hashlib.sha256,
        )
        return h.hexdigest()

    def api_proxy(
        self,
        url: Optional[str] = None,
        post_data: Optional[Dict] = None,
        expected_format: str = "json.loads",
        is_delete: bool = False,
        ssl_verify: Optional[bool] = None,
        access_token: Optional[str] = None,
        get_data: Optional[Dict] = None,
    ) -> Union[Dict, List]:
        """
        General proxy access

        If using this directly, you probably want to pass in an "access_token" kwarg in `post_data`
        """
        response = None
        response_parsed = None
        if ssl_verify is None:
            ssl_verify = self.ssl_verify

        # stash the original url
        # _url_original = url

        # quickly
        _url: str
        if not url:
            # url = "%s/" % self.fb_url_graph_api
            url = self.fb_url_graph_api
            _url = str(url)
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
                    if self.fb_url_graph_api:
                        url = self.fb_url_graph_api + url
                else:
                    raise ApiError("Not sure what sort of endpoint you are thinking of")
            _url = url

        # add in an access token to URLs if needed.
        if access_token:
            if not get_data or not get_data.get("access_token"):
                if "access_token=" not in _url:
                    _access_token = urlencode(dict(access_token=access_token))
                    if "?" not in _url:
                        _url += "?" + _access_token
                    else:
                        _url += "&" + _access_token
        else:
            # derive the access token if possible from the url
            if post_data and "access_token" in post_data:
                access_token = post_data["access_token"]
            elif get_data and "access_token" in get_data:
                access_token = get_data["access_token"]
            elif "access_token=" in _url:
                _parsed = urlparse(_url)
                if _parsed.query:
                    _qs: Dict[str, Any] = parse_qs(_parsed.query)
                    access_token = _qs.get(
                        "access_token"
                    )  # this will be `None` or a list
                    access_token = access_token[0] if access_token else None

        if self.app_secretproof:
            if access_token:
                if "access_token=" in _url:
                    if "appsecret_proof=" not in _url:
                        _appsecret_proof = self.generate__appsecret_proof(
                            access_token=access_token
                        )
                        if _appsecret_proof:
                            _url += "&appsecret_proof=" + _appsecret_proof
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
                response = requests.get(
                    _url,
                    params=get_data,
                    verify=ssl_verify,
                )
            else:
                if post_data:
                    if "batch" in post_data:
                        if isinstance(post_data["batch"], list):
                            post_data["batch"] = json.dumps(post_data["batch"])
                if is_delete:
                    response = requests.delete(_url, data=post_data, verify=ssl_verify)
                else:
                    response = requests.post(_url, data=post_data, verify=ssl_verify)

            # store the response for possible later debugging by user
            # e.g. `response.headers['X-FB-Debug']`
            self._penultimate_response = self._last_response
            self._last_response = response

            # response.text is the decoded response
            # response.content is the raw response
            response_text = response.text
            response_parsed = None  # scoping

            if response.status_code == 200:
                if expected_format in ("json.load", "json.loads"):
                    response_parsed = json.loads(response_text)
                    if (
                        (post_data is not None)
                        and isinstance(post_data, dict)
                        and ("batch" in post_data)
                    ):
                        if not isinstance(response_parsed, list):
                            raise ApiResponseError(
                                message="Batched Graph request expects a list of dicts. Did not get a list.",
                                response_content=response_parsed,
                            )
                        for li in response_parsed:
                            if not isinstance(li, dict):
                                raise ApiResponseError(
                                    message="Batched Graph request expects a list of dicts. Got a list, element not a dict.",
                                    response_content=response_parsed,
                                )
                            if not all(k in li for k in ("body", "headers", "code")):
                                raise ApiResponseError(
                                    message="Batched Graph response dict should contain 'body', 'headers', 'code'.",
                                    response_content=response_parsed,
                                )
                            # the body is a json encoded string itself.  it was previously escaped, so unescape it!
                            li["body"] = json.loads(li["body"])

                elif expected_format == "urlparse.parse_qs":
                    response_parsed = parse_qs(response_text)
                else:
                    raise ValueError("Unexpected Format: %s" % expected_format)
            else:
                if DEBUG:
                    print(response)
                    print(response.__dict__)
                if response.status_code == 400:
                    try:
                        try:
                            # try loading this into json.
                            # if it passes, awesome
                            # if it fails, we can error out
                            response_parsed = json.loads(response_text)
                        except Exception as exc:  # noqa: F841
                            pass
                        if response_parsed is None:
                            raise ApiError(
                                message="I don't know how to handle `None` for response content",
                                code=400,
                            )
                        if "error" in response_parsed:
                            error = reformat_error(response_parsed["error"])
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
                                raise ApiAuthError(**error)
                            raise ApiError(**error)
                        raise ApiError(
                            message="I don't know how to handle this error (%s)"
                            % response_parsed,
                            code=400,
                        )
                    except json.JSONDecodeError as exc:
                        raise ApiError(
                            message="Could not parse JSON from the error (%s)"
                            % response_parsed,
                            code=400,
                            raised=exc,
                        )
                    except Exception as exc:  # noqa: F841
                        raise
                if self.last_response_is_ratelimited:
                    raise ApiRatelimitedError(
                        message="Application is ratelimited. %s"
                        % self.last_response_usage,
                        code=response.status_code,
                    )
                raise ApiError(
                    message="Could not communicate with the API",
                    code=response.status_code,
                )
            return response_parsed
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
        submitted_code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        keep_response: Optional[bool] = None,
    ) -> Union[str, Tuple[str, Dict]]:
        """
        Gets the access token from Facebook that corresponds with a code.
        This uses `requests` to open the url, so should be considered as blocking code.
        If `keep_response` is set, will return a tuple of `access_token` and the response
        """
        if submitted_code is None:
            raise ValueError("must call with submitted_code")
        if scope is None:
            scope = self.app_scope
        if redirect_uri is None:
            redirect_uri = self.oauth_code_redirect_uri
        url_access_token = self.oauth_code__url_access_token(
            submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope
        )
        try:
            response = self.api_proxy(url_access_token, expected_format="json.loads")
            if not isinstance(response, dict):
                raise ApiError(message="invalid response; expected single dict")
            if "access_token" not in response:
                raise ApiError(message="invalid response")
            access_token = response["access_token"]
            if keep_response:
                return access_token, response
            return access_token
        except:  # noqa: E722
            raise

    @require_authenticated_hub
    def oauth_code__get_access_token_and_profile(
        self,
        submitted_code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> Tuple[str, Optional[Union[Dict, List]]]:
        """
        Gets the access token AND a profile from Facebook that corresponds with a code.
        This method wraps a call to `oauth_code__get_access_token`, then wraps `graph__get_profile_for_access_token` which opens a json object at the url returned by `graph__url_me_for_access_token`.
        This is a convenience method, since most people want to do that (at least on the initial Facebook auth.
        This wraps methods which use `requests` to open urls, so should be considered as blocking code.
        """
        if submitted_code is None:
            raise ValueError("must submit a code")
        (access_token, profile) = (None, None)
        try:
            access_token = self.oauth_code__get_access_token(
                submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope
            )
            profile = self.graph__get_profile_for_access_token(
                access_token=access_token, fields=fields
            )
        except:  # noqa: E722
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
        if scope is None:
            scope = self.app_scope
        if redirect_uri is None:
            redirect_uri = self.oauth_token_redirect_uri

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
        access_token: Optional[str] = None,
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
        if access_token is None:
            raise ValueError("must call with access_token")

        return FacebookApiUrls.oauth__url_extend_access_token(
            fb_url_graph_api=self.fb_url_graph_api,
            app_id=self.app_id,
            app_secret=self.app_secret,
            access_token=access_token,
        )

    @require_authenticated_hub
    def graph__extend_access_token(
        self,
        access_token: Optional[str] = None,
    ) -> Optional[Union[Dict, List]]:
        """
        see `oauth__url_extend_access_token`
        """
        if access_token is None or not access_token:
            raise ValueError("must submit access_token")
        try:
            url = self.oauth__url_extend_access_token(access_token=access_token)
            response = self.api_proxy(url, expected_format="json.load")
        except:  # noqa: E722
            raise
        return response

    @require_authenticated_hub
    def graph__url_me(
        self,
        access_token,
    ):
        raise ValueError("Deprecated; call graph__url_me_for_access_token instead")

    @require_authenticated_hub
    def graph__url_me_for_access_token(
        self,
        access_token: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> str:
        if access_token is None:
            raise ValueError("must submit access_token")

        return FacebookApiUrls.graph__url_me_for_access_token(
            fb_url_graph_api=self.fb_url_graph_api,
            access_token=access_token,
            fields=fields,
            app_secretproof=self.generate__appsecret_proof(access_token),
        )

    @require_authenticated_hub
    def graph__url_user_for_access_token(
        self,
        access_token: Optional[str] = None,
        user: Optional[str] = None,
        action: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> str:
        if access_token is None:
            raise ValueError("must submit access_token")
        if user is None:
            raise ValueError("must submit user")
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
        access_token: Optional[str] = None,
        user: Optional[str] = None,
        action: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> Optional[Union[Dict, List]]:
        """
        Grabs a profile for a user, corresponding to a profile, from Facebook.
        This uses `requests` to open the url, so should be considered as blocking code.
        """
        if access_token is None:
            raise ValueError("must submit access_token")
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
        except:  # noqa: E722
            raise
        return profile

    @require_authenticated_hub
    def graph__get_profile(
        self,
        access_token: Optional[str] = None,
    ):
        raise ValueError("Deprecated; call graph__get_profile_for_access_token instead")

    @require_authenticated_hub
    def graph__action_create(
        self,
        access_token: str,
        fb_app_namespace: str,
        fb_action_type_name: str,
        object_type_name: str,
        object_instance_url: str,
    ) -> Union[Dict, List]:
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
        post_data = {
            "access_token": access_token,
            object_type_name: object_instance_url,
        }
        if self.app_secretproof:
            post_data["appsecret_proof"] = self.generate__appsecret_proof(access_token)
        try:
            payload = self.api_proxy(url, post_data, expected_format="json.load")
            return payload
        except:  # noqa: E722
            raise

    @require_authenticated_hub
    def graph__action_list(
        self,
        access_token: str,
        fb_app_namespace: str,
        fb_action_type_name: str,
    ) -> Union[Dict, List]:
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
        except:  # noqa: E722
            raise

    @require_authenticated_hub
    def graph__action_delete(
        self,
        access_token: str,
        action_id: str,
    ) -> Union[Dict, List]:
        if not all((access_token, action_id)):
            raise ValueError("must submit action_id")

        url = FacebookApiUrls.graph__action_delete_url(
            fb_url_graph_api=self.fb_url_graph_api, action_id=action_id
        )
        post_data = {"access_token": access_token}
        if self.app_secretproof:
            post_data["appsecret_proof"] = self.generate__appsecret_proof(access_token)
        try:
            payload = self.api_proxy(
                url, post_data=post_data, expected_format="json.load", is_delete=True
            )
            return payload
        except:  # noqa: E722
            raise

    @require_authenticated_hub
    def verify_signed_request(
        self,
        signed_request: str,
        timeout: Optional[str] = None,
    ) -> Tuple[Optional[bool], Dict]:
        """
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
        if signed_request is None:
            raise ValueError("must submit `signed_request`")
        if not self.app_secret:
            raise ValueError("no configured `app_secret`")

        def base64_url_decode(inp: str) -> bytes:
            padding_factor = (4 - len(inp) % 4) % 4
            inp += "=" * padding_factor
            try:
                return base64.urlsafe_b64decode(inp)
            except binascii.Error:
                # this could happen if the payload is malformed
                return b""  # return something that will fail

        signature: str
        payload: str
        (signature, payload) = signed_request.split(".")
        decoded_signature: bytes = base64_url_decode(signature)
        data = json.loads(base64_url_decode(payload))

        if data.get("algorithm").upper() != "HMAC-SHA256":
            return (
                False,
                {
                    "python-error": "Unknown algorithm - %s"
                    % data.get("algorithm").upper()
                },
            )

        expected_sig: bytes = hmac.new(
            self.app_secret.encode(),
            msg=payload.encode(),
            digestmod=hashlib.sha256,
        ).digest()

        if decoded_signature != expected_sig:
            return (
                None,
                {
                    "python-error": "signature (%r) != expected_sig (%r)"
                    % (decoded_signature, expected_sig)
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
    def __init__(
        self,
        request,
        oauth_token_redirect_uri=None,
        oauth_code_redirect_uri=None,
        fb_api_version=None,
        app_secret=None,
        app_secretproof=None,
        app_domain=None,
        ssl_verify=None,
        secure_only=None,
        app_scope=None,
        app_id=None,
    ):
        """
        Creates a new ``FacebookHub`` object, sets it up with Pyramid Config vars, and then proxies other functions into it.
        """
        self.request = request
        registry_settings = request.registry.settings

        fb_utils_prefix = registry_settings.get("fbutils.prefix", "fbutils")

        fb_api_version = fb_api_version or FB_API_VERSION
        if fb_api_version is None:
            fb_api_version = registry_settings.get(
                "%s.api_version" % fb_utils_prefix, None
            )

        if app_id is None:
            app_id = registry_settings.get("%s.id" % fb_utils_prefix, None)
        if app_secret is None:
            app_secret = registry_settings.get("%s.secret" % fb_utils_prefix, None)
        if app_secretproof is None:
            app_secretproof = registry_settings.get(
                "%s.secretproof" % fb_utils_prefix, None
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
            app_secretproof=app_secretproof,
            app_scope=app_scope,
            app_domain=app_domain,
            oauth_code_redirect_uri=oauth_code_redirect_uri,
            oauth_token_redirect_uri=oauth_token_redirect_uri,
            ssl_verify=ssl_verify,
            secure_only=secure_only,
            fb_api_version=fb_api_version,
        )

    @require_authenticated_hub
    def oauth_code__url_access_token(
        self,
        submitted_code: Optional[str] = None,
        redirect_uri=None,
        scope=None,
    ) -> str:
        if submitted_code is None:
            submitted_code = self.request.params.get("code")
        return FacebookHub.oauth_code__url_access_token(
            self, submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope
        )

    @require_authenticated_hub
    def oauth_code__get_access_token(
        self,
        submitted_code=None,
        redirect_uri=None,
        scope=None,
    ) -> str:
        if submitted_code is None:
            submitted_code = self.request.params.get("code")
        return FacebookHub.oauth_code__get_access_token(
            self, submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope
        )

    @require_authenticated_hub
    def oauth_code__get_access_token_and_profile(
        self,
        submitted_code=None,
        redirect_uri=None,
        scope=None,
        fields=None,
    ) -> str:
        if submitted_code is None:
            submitted_code = self.request.params.get("code")
        return FacebookHub.oauth_code__get_access_token_and_profile(
            self,
            submitted_code=submitted_code,
            redirect_uri=redirect_uri,
            scope=scope,
            fields=fields,
        )
