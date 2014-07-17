r"""
    facebook_utils
    ~~~~~~~~~~~~

    v 0.20.0

    A collection of utilities for integrating user accounts with Facebook.com

    right now this handles oauth and graph operations

    Purpose
    =======

    1. Facebook dropped development and support of their python sdk

    2. There are a handful of pyramid utilities that provide a complete drop-in
    integration with Facebook.com; This is NOT one of them. Sometimes you want
    to control the User Experience and have all your pages custom; if so, this
    is for you.


    Usage
    =====

    This was originally built/intended for use under the Pyramid environment

    calling `FacebookPyramid()` will create a new object that
    subclasses `FacebookHub()` objects, using  default settings
    from your .ini and pulling variables from 'request' as needed.

    `facebook_utils.FacebookHub()` can be used directly - however it will not
    pull the appropriate settings from the .ini or request.


    Supports Two oAuth Flows
    =========================

    Flow 1 - Server Side
    --------------------
    1. configure an object with `oauth_code_redirect_uri`
    2. consumers click a button on your site, which redirects to
    `oauth_code_redirect_uri` -- as provided by `oauth_code__url_dialog()`
    3. upon success, users are redirected from facebook to
    `oauth_code_redirect_uri` along with a query param titled `code`
    4. you may then call `.oauth_code__get_access_token()` to get an access
    token or call `oauth_code__get_access_token_and_profile()` to get the token
    and profile data.
    5. profile data can be updated with `.graph__get_profile(access_token)`


    Flow 2 - Client Side
    --------------------
    1. configure an object with `oauth_token_redirect_uri`
    2. consumers click a button on your site, which redirects to
    `oauth_token_redirect_uri` -- as provided by `oauth_token__url_dialog()`
    3. upon success, users are redirected from facebook to
    `oauth_token__url_dialog` along with a query param titled `token` and a
    hash value titled `#access_token`.  The `access_token` is not visible to
    the server, and must be transferred to your server via JavaScript or
    not-at-all should you simply want to do all your integration in JavaScript.
    4. profile data can be obtained with `.graph__get_profile(access_token)`
    if you store the access token


    Notes
    =====
    Most methods will let you override the 'scope' and 'request_uri'.  This
    shouldn't really be necessary and will probably be deprecated.


    Pyramid Examples
    ================
    define some variables in your .ini files:

    file: development.ini

        facebook.app.id = 123
        facebook.app.secret = 123
        facebook.app.scope = email, user_birthday, user_checkins, offline_access
        facebook.app.oauth_code_redirect_uri = http://127.0.0.1:5010/facebook-oauth-redirect


    integrate into your handlers:

        from facebook_utils import FacebookPyramid

        class WebAccount(base.Handler):
            def __new_fb_object(self):
                "Create a new Facebook Object"
                # note that we can override settings in the .ini files
                oauth_code_redirect_uri= "http://%(app_domain)s/account/facebook-authenticate-oauth?response_type=code" % {'app_domain': self.request.registry.settings['app_domain']}
                oauth_token_redirect_uri= "http://%(app_domain)s/account/facebook-authenticate-oauth-token?response_type=token" % {'app_domain': self.request.registry.settings['app_domain']}
                fb= FacebookPyramid(self.request, oauth_code_redirect_uri=oauth_code_redirect_uri)
                return fb

            def sign_up(self):
                "sign up page, which contains a "signup with facebook link"
                fb= self.__new_fb_object()
                return {"project":"MyApp", 'facebook_pyramid':facebook}

            @action(renderer="web/account/facebook_authenticate_oauth.html")
            def facebook_authenticate_oauth(self):
                fb= self.__new_fb_object()
                (access_token, profile)= fb.oauth_code__get_access_token_and_profile(self.request)
                if profile:
                    # congrats, they logged in
                    # register the user to your db
                    raise HTTPFound(location='/account/home')
                else:
                    # boo, that didn't work
                    raise HTTPFound(location='/account/sign-up?error=facebook-oauth-failure')
                return {"project":"MyApp"}


    integrate into your template:
                <a class="fancy_button-1" id="signup-start_btn-facebook" href="${facebook_pyramid.oauth_code__url_dialog()}">
                    Connect with <strong>Facebook</strong>
                </a>

    Graph Operations
    ================

    Every `hub` object has an `api_proxy` method, which can be used to
    centralize communication to the Facebook API

    Facebook's API isn't very 'standardized' across the board. Some endpoints
    return json data, others return urlquoted data.  `api_proxy` doesn't care.
    it returns a dict from every endpoint, and does the conversion for you.

    The `api_proxy` defaults to a json load.  certain api calls will pass in
    a different `expected_format` argument.  The proxy will also handle 'batch'
    style graph requests.

    When the api_proxy encounters an error, it returns `ApiError` or a more
    contextual subclass of the that exception class.

    The current exception class inheritance is:

        ApiError
            ApiAuthError
                ApiAuthExpiredError
            ApiApplicationError
            ApiResponseError
            ApiRuntimeError
                ApiRuntimeVerirficationFormatError
                ApiRuntimeGrantError
                ApiRuntimeScopeError
                ApiRuntimeGraphMethodError
            ApiUnhandledError

    `ApiError` instances contain:
        code (facebook specific, not http code)
        type (as dictacted by facebook)
        message (possibly dictated by facebook)
        raised (the trapped error that raised this, if available)
        response (the repsonse in error, if available)

    the `api_proxy` will catch *most* errors.  since this is in development,
    i'm raising uncaught exceptions.  There will be a future "ApiUnhandledError"


    Unit Tests
    ===========

    Unit Tests require the following environment vars to be set:

        PYTHON_FB_UTILS_APP_ID
        PYTHON_FB_UTILS_APP_SECRET
        PYTHON_FB_UTILS_APP_SCOPE
        PYTHON_FB_UTILS_ACCESS_TOKEN

            export PYTHON_FB_UTILS_APP_ID="app_id_from_facebook.com"
            export PYTHON_FB_UTILS_APP_SECRET="app_secret_from_facebook.com"
            export PYTHON_FB_UTILS_APP_SCOPE="email,user_activities,user_status,read_stream"
            export PYTHON_FB_UTILS_ACCESS_TOKEN="from_API_operations"

    ToDo
    =======
    - I think in the future, the 'dicts' that come back should be cast into a 'response' object, and there will be some metadata attached to it.


:copyright: 2012-2013 by Jonathan Vanasco
    license: BSD
"""

import base64
import cgi
import datetime
import hashlib
import hmac
try:
    import simplejson as json
except ImportError:
    import json
import urllib
import urlparse
from time import time
import types

import requests


class ApiError(Exception):
    """
    Raised if there is an error with authentication
    """
    code = None
    type = None
    message = None
    response = None
    raised = None

    def __init__(self, code=None, type=None, message=None, response=None, raised=None):
        self.code = code
        self.type = type
        self.message = message
        self.response = response
        self.raised = raised

    def __str__(self):
        return "ApiError: %s | %s | %s" % (self.code, self.type, self.message)


class ApiAuthError(ApiError):
    """
    Raised if there is an error with authentication
    """
    pass


class ApiAuthExpiredError(ApiAuthError):
    """
    Raised if there is an error with authentication due to expiry
    """
    pass


class ApiApplicationError(ApiError):
    """
    Raised if there is an error with the application setup
    """
    pass


class ApiResponseError(ApiError):
    """
    Raised if the response is weird
    """
    pass


class ApiRuntimeError(ApiError):
    """
    Raised if there is an error on the application when run
    """
    pass


class ApiRuntimeVerirficationFormatError(ApiRuntimeError):
    """
    Raised if there is an error on the applicaiton when run: Invalid verification code format
    """
    pass


class ApiRuntimeGrantError(ApiRuntimeError):
    """
    Raised if there is an error on the application when run: Invalid verification code format
    """
    pass


class ApiRuntimeScopeError(ApiRuntimeError):
    """
    Raised if there is an error on the application when run: Invalid verification code format
    """
    pass


class ApiRuntimeGraphMethodError(ApiError):
    """
    Raised if there is an error on the application when run: Invalid graph method
    """
    pass


class ApiUnhandledError(ApiError):
    """
    Raised if something bad happened, so you only have to track one error.
    Note that this inherits from ApiError - so this should be the first thing you catch

    Good - raises ApiUnhandledError
        try:
            raise ApiUnhandledError()
        except ApiUnhandledError, e:
            print "raised ApiUnhandledError"
        except ApiError, e:
            print "raised ApiError"

    Bad - raises ApiError
        try:
            raise ApiUnhandledError()
        except ApiError, e:
            print "raised ApiError"
        except ApiUnhandledError, e:
            print "raised ApiUnhandledError"

    """
    pass

    def __str__(self):
        return "ApiError: %s " % (self.raised)


def reformat_error(json_string, raised=None):
    rval = {'message': None, 'type': None, 'code': None, 'raised': None, }
    for k in rval.keys():
        if k in json_string:
            rval[k] = json_string[k]
    if raised is not None:
        rval['raised'] = raised
    return rval


def facebook_time(fb_time):
    """parses facebook's timestamp into a datetime object"""
    return datetime.datetime.strptime(fb_time, '%Y-%m-%dT%H:%M:%S+0000')


class FacebookHub(object):
    app_id = None
    app_secret = None
    app_scope = None
    app_domain = None
    oauth_code_redirect_uri = None
    oauth_token_redirect_uri = None
    debug_error = False
    mask_unhandled_exceptions = False
    ssl_verify = True

    def __init__(self, app_id=None, app_secret=None, app_scope=None, app_domain=None, oauth_code_redirect_uri=None, oauth_token_redirect_uri=None, debug_error=False, mask_unhandled_exceptions=False, ssl_verify=True):
        """Initialize the FacebookHub object with some variables.  app_id and app_secret are required."""
        if app_id is None or app_secret is None:
            raise ValueError("Must initialize FacebookHub() with an app_id and an app_secret")
        self.app_id = app_id
        self.app_secret = app_secret
        self.app_scope = app_scope
        self.app_domain = app_domain
        self.oauth_code_redirect_uri = oauth_code_redirect_uri
        self.oauth_token_redirect_uri = oauth_token_redirect_uri
        self.debug_error = debug_error
        self.mask_unhandled_exceptions = mask_unhandled_exceptions
        self.ssl_verify = ssl_verify

    def oauth_code__url_dialog(self, redirect_uri=None, scope=None):
        """Generates the URL for an oAuth dialog to facebook for a "code" flow.  This flow will return the user to your website with a 'code' object in a query param. """
        if scope is None:
            scope = self.app_scope
        if redirect_uri is None:
            redirect_uri = self.oauth_code_redirect_uri
        return """https://www.facebook.com/dialog/oauth?client_id=%(app_id)s&scope=%(scope)s&redirect_uri=%(redirect_uri)s""" % {'app_id': self.app_id, "redirect_uri": urllib.quote(redirect_uri), 'scope': scope, }

    def oauth_code__url_access_token(self, submitted_code=None, redirect_uri=None, scope=None):
        """Generates the URL to grab an access token from Facebook.  This is returned based on EXACTLY matching the app_id, app_secret, and 'code' with the redirect_uri. If you change the redirect uri - or any other component - it will break.
        https://graph.facebook.com/oauth/access_token?client_id=YOUR_APP_ID&redirect_uri=YOUR_URL&client_secret=YOUR_APP_SECRET&code=THE_CODE_FROM_URL_DIALOG_TOKEN

        """
        if submitted_code is None:
            raise ValueError('must call with submitted_code')
        if redirect_uri is None:
            redirect_uri = self.oauth_code_redirect_uri
        if scope is None:
            scope = self.app_scope
        return """https://graph.facebook.com/oauth/access_token?client_id=%(app_id)s&redirect_uri=%(redirect_uri)s&client_secret=%(client_secret)s&code=%(code)s""" % {'app_id': self.app_id, "redirect_uri": urllib.quote(redirect_uri), 'client_secret': self.app_secret, 'code': submitted_code, }

    def api_proxy(self, url, post_data=None, expected_format='json.load', is_delete=False, ssl_verify=None):
        response = None
        response_content = None
        if ssl_verify is None:
            ssl_verify = self.ssl_verify
        try:
            if not post_data:
                # normal get
                response = requests.get(url, verify=ssl_verify)
            else:
                if post_data:
                    if 'batch' in post_data:
                        if isinstance(post_data['batch'], types.ListType):
                            post_data['batch'] = json.dumps(post_data['batch'])
                if is_delete:
                    response = requests.delete(url, data=post_data, verify=ssl_verify)
                else:
                    response = requests.post(url, data=post_data, verify=ssl_verify)
            response_content = response.text
            if response.status_code == 200:
                if expected_format in ('json.load', 'json.loads'):
                    response_content = json.loads(response_content)
                    if (post_data is not None) and isinstance(post_data, types.DictType) and ('batch' in post_data):
                        if not isinstance(response_content, types.ListType):
                            raise ApiResponseError(message="Batched Graph request expects a list of dicts. Did not get a list.", response=response_content)
                        for li in response_content:
                            if not isinstance(li, types.DictType):
                                raise ApiResponseError(message="Batched Graph request expects a list of dicts. Got a list, element not a dict.", response=response_content)
                            if not all(k in li for k in ('body', 'headers', 'code')):
                                raise ApiResponseError(message="Batched Graph response dict should contain 'body', 'headers', 'code'.", response=response_content)
                            # the body is a json encoded string itself.  it was previously escaped, so unescape it!
                            li['body'] = json.loads(li['body'])

                elif expected_format == 'cgi.parse_qs':
                    response_content = cgi.parse_qs(response_content)
                elif expected_format == 'urlparse.parse_qs':
                    response_content = urlparse.parse_qs(response_content)
                else:
                    raise ValueError("Unexpected Format: %s" % expected_format)
            else:
                print response
                print response.__dict__
                if response.status_code == 400:
                    rval = ''
                    try:
                        rval = json.loads(response_content)
                        if 'error' in rval:
                            error = reformat_error(rval['error'])
                            if ('code' in error) and error['code']:
                                if error['code'] == 1:
                                    # Error validating client secret
                                    raise ApiApplicationError(**error)
                                elif error['code'] == 101:
                                    # Error validating application. Invalid application ID
                                    raise ApiApplicationError(**error)
                                elif error['code'] == 100:
                                    if ('type' in error) and error['type']:
                                        if error['type'] == 'GraphMethodException':
                                            raise ApiRuntimeGraphMethodError(**error)

                                    if ('message' in error) and error['message']:
                                        if error['message'][:32] == 'Invalid verification code format':
                                            raise ApiRuntimeVerirficationFormatError(**error)
                                        elif error['message'][:19] == 'Invalid grant_type:':
                                            raise ApiRuntimeGrantError(**error)
                                        elif error['message'][:18] == 'Unsupported scope:':
                                            raise ApiRuntimeScopeError(**error)
                                        elif error['message'][:18] == 'Unsupported scope:':
                                            raise ApiRuntimeScopeError(**error)

                                elif error['code'] == 104:
                                    raise ApiAuthError(**error)

                            if ('message' in error) and error['message']:
                                if error['message'][:63] == 'Error validating access token: Session has expired at unix time':
                                    raise ApiAuthExpiredError(**error)
                                elif error['message'][:26] == 'Invalid OAuth access token':
                                    raise ApiAuthError(**error)
                                elif error['message'][:29] == 'Error validating access token':
                                    raise ApiAuthError(**error)
                            if ('type' in error) and (error['type'] == 'OAuthException'):
                                raise ApiAuthError(**error)
                            raise ApiError(**error)
                        raise ApiError(message = 'I don\'t know how to handle this error (%s)' % rval, code=400)
                    except json.JSONDecodeError, e:
                        raise ApiError(message = 'Could not parse JSON from the error (%s)' % rval, code=400, raised=e)
                    except:
                        raise
                raise ApiError(message = 'Could not communicate with the API', code=response.status_code)
            return response_content
        except json.JSONDecodeError, e:
            raise ApiError(message = 'Could not parse JSON from the error (%s)' % e, raised=e)
        except Exception as e:
            if self.mask_unhandled_exceptions:
                raise ApiUnhandledError(raised=e)
            raise

    def oauth_code__get_access_token(self, submitted_code=None, redirect_uri=None, scope=None):
        """Gets the access token from Facebook that corresponds with a code.  This uses `requests` to open the url, so should be considered as blocking code."""
        if submitted_code is None:
            raise ValueError('must call with submitted_code')
        if scope is None:
            scope = self.app_scope
        if redirect_uri is None:
            redirect_uri = self.oauth_code_redirect_uri
        url_access_token = self.oauth_code__url_access_token(submitted_code, redirect_uri=redirect_uri, scope=scope)
        access_token = None
        try:
            response = self.api_proxy(url_access_token, expected_format='cgi.parse_qs')
            if 'access_token' not in response:
                raise ApiError(message='invalid response')
            access_token = response["access_token"][-1]
        except:
            raise
        return access_token

    def oauth_code__get_access_token_and_profile(self, submitted_code=None, redirect_uri=None, scope=None):
        """Gets the access token AND a profile from Facebook that corresponds with a code.  This method wraps a call to `oauth_code__get_access_token`, then wraps `graph__get_profile_for_access_token` which opens a json object at the url returned by `graph__url_me_for_access_token`.  This is a convenince method, since most people want to do that (at least on the initial Facebook auth.  This wraps methods which use `requests` to open urls, so should be considered as blocking code."""
        if submitted_code is None:
            raise ValueError('must submit a code')
        (access_token, profile) = (None, None)
        try:
            access_token = self.oauth_code__get_access_token(submitted_code, redirect_uri=redirect_uri, scope=scope)
            profile = self.graph__get_profile_for_access_token(access_token=access_token)
        except:
            raise
        return (access_token, profile)

    def oauth_token__url_dialog(self, redirect_uri=None, scope=None):
        """Generates the URL for an oAuth dialog to facebook.  This flow will return the user to your website with a 'token' object as a URI hashstring.  This hashstring can not be seen by the server, it must be handled via javascript """
        if scope is None:
            scope = self.app_scope
        if redirect_uri is None:
            redirect_uri = self.oauth_token_redirect_uri
        return """https://www.facebook.com/dialog/oauth?client_id=%(app_id)s&scope=%(scope)s&redirect_uri=%(redirect_uri)s&response_type=token""" % {'app_id': self.app_id, "redirect_uri": urllib.quote(redirect_uri), 'scope': scope, }

    def oauth__url_extend_access_token(self, access_token=None):
        """Generates the URL to extend an access token from Facebook.

        see https://developers.facebook.com/roadmap/offline-access-removal/

        https://graph.facebook.com/oauth/access_token?
            client_id=APP_ID&
            client_secret=APP_SECRET&
            grant_type=fb_exchange_token&
            fb_exchange_token=EXISTING_ACCESS_TOKEN

        oddly, this returns a url formatted string and not a json document.  go figure.

        """
        if access_token is None:
            raise ValueError('must call with access_token')
        return """https://graph.facebook.com/oauth/access_token?client_id=%(app_id)s&client_secret=%(client_secret)s&grant_type=fb_exchange_token&fb_exchange_token=%(access_token)s""" % {'app_id': self.app_id, 'client_secret': self.app_secret, 'access_token': access_token, }

    def graph__extend_access_token(self, access_token=None):
        """ see oauth__url_extend_access_token  """
        if access_token is None or not access_token:
            raise ValueError('must submit access_token')
        try:
            url = self.oauth__url_extend_access_token(access_token=access_token)
            response = self.api_proxy(url, expected_format='urlparse.parse_qs')
        except:
            raise
        return response

    def graph__url_me(self, access_token):
        raise ValueError('Deprecated; call graph__url_me_for_access_token instead')

    def graph__url_me_for_access_token(self, access_token=None):
        if access_token is None:
            raise ValueError('must submit access_token')
        return "https://graph.facebook.com/me?" + urllib.urlencode(dict(access_token=access_token))

    def graph__url_user_for_access_token(self, access_token=None, user=None, action=None):
        if access_token is None:
            raise ValueError('must submit access_token')
        if user is None:
            raise ValueError('must submit user')
        if action:
            return "https://graph.facebook.com/%s/%s?%s" % (user, action, urllib.urlencode(dict(access_token=access_token)))
        return "https://graph.facebook.com/%s?%s" % (user, urllib.urlencode(dict(access_token=access_token)))

    def graph__get_profile_for_access_token(self, access_token=None, user=None, action=None):
        """Grabs a profile for a user, corresponding to a profile, from Facebook.  This uses `requests` to open the url, so should be considered as blocking code."""
        if access_token is None:
            raise ValueError('must submit access_token')
        profile = None
        try:
            url = None
            if not user:
                if action:
                    url = self.graph__url_user_for_access_token(access_token, action=action)
                else:
                    url = self.graph__url_me_for_access_token(access_token)
            else:
                url = self.graph__url_user_for_access_token(access_token, user=user, action=action)
            profile = self.api_proxy(url, expected_format='json.load')
        except:
            raise
        return profile

    def graph__get_profile(self, access_token=None):
        raise ValueError('Deprecated; call graph__get_profile_for_access_token instead')

    def graph__action_create(self, access_token=None, fb_app_namespace=None, fb_action_type_name=None, object_type_name=None, object_instance_url=None):
        if not all((access_token, fb_app_namespace, fb_action_type_name)):
            raise ValueError('must submit access_token, fb_app_namespace, fb_action_type_name')
        if not all((object_type_name, object_instance_url)):
            raise ValueError('must submit object_type_name, object_instance_url ')
        url = "https://graph.facebook.com/me/%s:%s" % (fb_app_namespace, fb_action_type_name)
        post_data = {
            'access_token': access_token,
            object_type_name: object_instance_url,
        }
        try:
            payload = self.api_proxy(url, post_data, expected_format='json.load')
            return payload
        except:
            raise

    def graph__action_list(self, access_token=None, fb_app_namespace=None, fb_action_type_name=None):
        if not all((access_token, fb_app_namespace, fb_action_type_name)):
            raise ValueError('must submit access_token, fb_app_namespace, fb_action_type_name')
        url = "https://graph.facebook.com/me/%s:%s?access_token=%s" % (fb_app_namespace, fb_action_type_name, access_token)
        try:
            payload = self.api_proxy(url, expected_format='json.load')
            return payload
        except:
            raise

    def graph__action_delete(self, access_token=None, action_id=None):
        if not all((access_token, action_id)):
            raise ValueError('must submit action_id')
        url = "https://graph.facebook.com/%s" % (action_id)
        post_data = {
            'access_token': access_token,
        }
        try:
            payload = self.api_proxy(url, post_data=post_data, expected_format='json.load', is_delete=True)
            return payload
        except:
            raise

    def verify_signed_request(self, signed_request=None, timeout=None):
        """ verifies the signedRequest from Facebook.  accepts a timeout value, to test against the 'issued_at' key within the payload

        this will always return a Tuple of (BOOL, DICT)

        Bool:
            True = Signed Request is verified
            False = Signed Request is not verified

        Dict:
            if request is verified: the payload object as JSON
            if request is not verified: a 'python-error' key with the reason

        PLEASE NOTE:
            1. if the request is verfied, but the data is outside of the timeout, this will return FALSE as a bool; and the dict will the verified payload with an 'python-error' key.
            2. i chose 'python-error', because facebook is likely to change their spec. they do that. the chances of them adding 'error' are much greater than 'python-error'

        Reference documentation
        https://developers.facebook.com/docs/authentication/signed_request/
        "The signed_request parameter is the concatenation of a HMAC SHA-256 signature string, a period (.), and a base64url encoded JSON object."

        after starting this, i found someone already did the hard work.
        following is based on Sunil Arora's blog post - http://sunilarora.org/parsing-signedrequest-parameter-in-python-bas
        """
        if signed_request is None:
            raise ValueError('must submit signed_request')

        def base64_url_decode(inp):
            padding_factor = (4 - len(inp) % 4) % 4
            inp += "=" * padding_factor
            return base64.b64decode(unicode(inp).translate(dict(zip(map(ord, u'-_'), u'+/'))))

        (signature, payload) = signed_request.split('.')

        decoded_signature = base64_url_decode(signature)
        data = json.loads(base64_url_decode(payload))

        if data.get('algorithm').upper() != 'HMAC-SHA256':
            return (False, {'python-error': 'Unknown algorithm - %s' % data.get('algorithm').upper()})

        expected_sig = hmac.new(self.app_secret, msg=payload, digestmod=hashlib.sha256).digest()

        if decoded_signature != expected_sig:
            return (None, {'python-error': 'signature (%s) != expected_sig (%s)' % (decoded_signature, expected_sig)})

        if timeout:
            time_now = int(time())
            diff = time_now - data['issued_at']
            if (diff > timeout):
                data['python-error'] = "payload issued outside of timeout window"
                return (False, data)

        return (True, data)


class FacebookPyramid(FacebookHub):

    def __init__(self, request, app_id=None, app_secret=None, app_scope=None, app_domain=None, oauth_code_redirect_uri=None, oauth_token_redirect_uri=None, ssl_verify=None):
        """Creates a new FacebookHub object, sets it up with Pyramid Config vars, and then proxies other functions into it"""
        self.request = request
        if app_id is None and 'facebook.app.id' in request.registry.settings:
            app_id = request.registry.settings['facebook.app.id']
        if app_secret is None and 'facebook.app.secret' in request.registry.settings:
            app_secret = request.registry.settings['facebook.app.secret']
        if app_scope is None and 'facebook.app.scope' in request.registry.settings:
            app_scope = request.registry.settings['facebook.app.scope']
        if app_domain is None:
            app_domain = request.registry.settings['app_domain']
        if oauth_code_redirect_uri is None and 'facebook.app.oauth_code_redirect_uri' in request.registry.settings:
            oauth_code_redirect_uri = request.registry.settings['facebook.app.oauth_code_redirect_uri']
        if oauth_token_redirect_uri is None and 'facebook.app.oauth_token_redirect_uri' in request.registry.settings:
            oauth_token_redirect_uri = request.registry.settings['facebook.app.oauth_token_redirect_uri']
        if ssl_verify is None and 'facebook.app.ssl_verify' in request.registry.settings:
            ssl_verify = request.registry.settings['facebook.app.ssl_verify']
        FacebookHub.__init__(self, app_id=app_id, app_secret=app_secret, app_scope=app_scope, app_domain=app_domain, oauth_code_redirect_uri=oauth_code_redirect_uri, oauth_token_redirect_uri=oauth_token_redirect_uri, ssl_verify=ssl_verify)

    def oauth_code__url_access_token(self, submitted_code=None, redirect_uri=None, scope=None):
        if submitted_code is None:
            submitted_code = self.request.params.get('code')
        return FacebookHub.oauth_code__url_access_token(self, submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope)

    def oauth_code__get_access_token(self, submitted_code=None, redirect_uri=None, scope=None):
        if submitted_code is None:
            submitted_code = self.request.params.get('code')
        return FacebookHub.oauth_code__get_access_token(self, submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope)

    def oauth_code__get_access_token_and_profile(self, submitted_code=None, redirect_uri=None, scope=None):
        if submitted_code is None:
            submitted_code = self.request.params.get('code')
        return FacebookHub.oauth_code__get_access_token_and_profile(self, submitted_code=submitted_code, redirect_uri=redirect_uri, scope=scope)
