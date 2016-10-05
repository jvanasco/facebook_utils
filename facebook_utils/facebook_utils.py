# -*- coding: utf-8 -*-


import datetime
import requests
import urlparse
import urllib
import hashlib
import base64
import types
import time
import hmac
import cgi

try:
    import simplejson as json
except ImportError:
    import json


from facebook_api_urls import FacebookApiUrls, FB_GRAPH_API_URL
from facebook_exceptions import *


DEBUG = False


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

    def __init__(self,
                 mask_unhandled_exceptions=False,
                 oauth_token_redirect_uri=None,
                 oauth_code_redirect_uri=None,
                 fb_grap_api_version=None,
                 debug_error=False,
                 app_domain=None,
                 app_secret=None,
                 ssl_verify=True,
                 app_scope=None,
                 app_id=None,
                 ):
        """
        Initialize the ``FacebookHub`` object with some variables.

        required kwargs:
            `app_id`
            `app_secret`
        """
        if app_id is None or app_secret is None:
            raise ValueError("Must initialize FacebookHub() with an app_id and an app_secret")

        if fb_grap_api_version is None:
            self.fb_graph_api = FB_GRAPH_API_URL
        else:
            self.fb_graph_api = u'{fb_graph_api_url}/{version}/'.format(fb_graph_api_url=FB_GRAPH_API_URL,
                                                                        version=fb_grap_api_version,
                                                                        )

        self.mask_unhandled_exceptions = mask_unhandled_exceptions
        self.oauth_token_redirect_uri = oauth_token_redirect_uri
        self.oauth_code_redirect_uri = oauth_code_redirect_uri
        self.debug_error = debug_error
        self.app_secret = app_secret
        self.app_domain = app_domain
        self.ssl_verify = ssl_verify
        self.app_scope = app_scope
        self.app_id = app_id

    def oauth_code__url_dialog(self, redirect_uri=None, scope=None, auth_type=None,):
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

        return FacebookApiUrls.oauth_code__url_dialog(app_id=self.app_id,
                                                      redirect_uri=redirect_uri,
                                                      scope=scope,
                                                      auth_type=auth_type,
                                                      )

    def oauth_code__url_access_token(self, submitted_code=None, redirect_uri=None, scope=None):
        """
        Generates the URL to grab an access token from Facebook.
        This is returned based on EXACTLY matching the app_id, app_secret, and 'code' with the redirect_uri.
        If you change the redirect uri - or any other component - it will break.
        https://graph.facebook.com/oauth/access_token?client_id=YOUR_APP_ID&redirect_uri=YOUR_URL&client_secret=YOUR_APP_SECRET&code=THE_CODE_FROM_URL_DIALOG_TOKEN
        """
        if submitted_code is None:
            raise ValueError('must call with submitted_code')
        if redirect_uri is None:
            redirect_uri = self.oauth_code_redirect_uri
        if scope is None:
            scope = self.app_scope

        return FacebookApiUrls.oauth_code__url_access_token(fb_graph_api=self.fb_graph_api,
                                                            app_id=self.app_id,
                                                            redirect_uri=redirect_uri,
                                                            app_secret=self.app_secret,
                                                            submitted_code=submitted_code,
                                                            )

    def api_proxy(self, url, post_data=None, expected_format='json.load', is_delete=False, ssl_verify=None, access_token=None):
        """
        General proxy access
        
        If using this directly, you probably want to pass in an "access_token" kwarg in `post_data`
        """
        response = None
        response_content = None
        if ssl_verify is None:
            ssl_verify = self.ssl_verify

        # add in an access token to URLs if needed.
        _url = url
        if access_token:
            _access_token = urllib.urlencode(dict(access_token=access_token))
            if '?' not in _url:
                _url = _url + '?' + _access_token
            else:
                _url = _url + '&' + _access_token
        try:
            if not post_data:
                # normal get
                response = requests.get(_url, verify=ssl_verify)
            else:
                # todo - figure out how to specify access token here.  this probably breaks.
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
                            raise ApiResponseError(message="Batched Graph request expects a list of dicts. Did not get a list.",
                                                   response=response_content)
                        for li in response_content:
                            if not isinstance(li, types.DictType):
                                raise ApiResponseError(message="Batched Graph request expects a list of dicts. Got a list, element not a dict.",
                                                       response=response_content)
                            if not all(k in li for k in ('body', 'headers', 'code')):
                                raise ApiResponseError(message="Batched Graph response dict should contain 'body', 'headers', 'code'.",
                                                       response=response_content)
                            # the body is a json encoded string itself.  it was previously escaped, so unescape it!
                            li['body'] = json.loads(li['body'])

                elif expected_format == 'cgi.parse_qs':
                    response_content = cgi.parse_qs(response_content)
                elif expected_format == 'urlparse.parse_qs':
                    response_content = urlparse.parse_qs(response_content)
                else:
                    raise ValueError("Unexpected Format: %s" % expected_format)
            else:
                if DEBUG:
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
        """
        Gets the access token from Facebook that corresponds with a code.
        This uses `requests` to open the url, so should be considered as blocking code.
        """
        if submitted_code is None:
            raise ValueError('must call with submitted_code')
        if scope is None:
            scope = self.app_scope
        if redirect_uri is None:
            redirect_uri = self.oauth_code_redirect_uri
        url_access_token = self.oauth_code__url_access_token(submitted_code=submitted_code,
                                                             redirect_uri=redirect_uri,
                                                             scope=scope,
                                                             )
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
        """
        Gets the access token AND a profile from Facebook that corresponds with a code.
        This method wraps a call to `oauth_code__get_access_token`, then wraps `graph__get_profile_for_access_token` which opens a json object at the url returned by `graph__url_me_for_access_token`.
        This is a convenience method, since most people want to do that (at least on the initial Facebook auth.
        This wraps methods which use `requests` to open urls, so should be considered as blocking code.
        """
        if submitted_code is None:
            raise ValueError('must submit a code')
        (access_token, profile) = (None, None)
        try:
            access_token = self.oauth_code__get_access_token(submitted_code=submitted_code,
                                                             redirect_uri=redirect_uri,
                                                             scope=scope,
                                                             )
            profile = self.graph__get_profile_for_access_token(access_token=access_token)
        except:
            raise
        return (access_token, profile)

    def oauth_token__url_dialog(self, redirect_uri=None, scope=None, auth_type=None):
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

        return FacebookApiUrls.oauth_token__url_dialog(app_id=self.app_id,
                                                       redirect_uri=redirect_uri,
                                                       scope=scope,
                                                      auth_type=auth_type,
                                                       )

    def oauth__url_extend_access_token(self, access_token=None):
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
            raise ValueError('must call with access_token')

        return FacebookApiUrls.oauth__url_extend_access_token(
            fb_graph_api=self.fb_graph_api,
            app_id=self.app_id,
            app_secret=self.app_secret,
            access_token=access_token
        )

    def graph__extend_access_token(self, access_token=None):
        """
        see `oauth__url_extend_access_token`
        """
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

        return FacebookApiUrls.graph__url_me_for_access_token(
            fb_graph_api=self.fb_graph_api,
            access_token=access_token
        )

    def graph__url_user_for_access_token(self, access_token=None, user=None, action=None):
        if access_token is None:
            raise ValueError('must submit access_token')
        if user is None:
            raise ValueError('must submit user')
        if action:
            return FacebookApiUrls.graph__url_user_for_access_token(
                fb_graph_api=self.fb_graph_api,
                access_token=access_token,
                user=user,
                action=action
            )

        return FacebookApiUrls.graph__url_user_for_access_token(
            fb_graph_api=self.fb_graph_api,
            access_token=access_token,
            user=user,
            action=None
        )

    def graph__get_profile_for_access_token(self, access_token=None, user=None, action=None):
        """
        Grabs a profile for a user, corresponding to a profile, from Facebook.
        This uses `requests` to open the url, so should be considered as blocking code.
        """
        if access_token is None:
            raise ValueError('must submit access_token')
        profile = None
        try:
            url = None
            if not user:
                if action:
                    url = self.graph__url_user_for_access_token(access_token,
                                                                action=action,
                                                                )
                else:
                    url = self.graph__url_me_for_access_token(access_token)
            else:
                url = self.graph__url_user_for_access_token(access_token,
                                                            user=user,
                                                            action=action
                                                            )
            profile = self.api_proxy(url, expected_format='json.load')
        except:
            raise
        return profile

    def graph__get_profile(
        self,
        access_token=None
    ):
        raise ValueError('Deprecated; call graph__get_profile_for_access_token instead')

    def graph__action_create(
        self,
        access_token=None,
        fb_app_namespace=None,
        fb_action_type_name=None,
        object_type_name=None,
        object_instance_url=None,
    ):
        if not all((access_token, fb_app_namespace, fb_action_type_name)):
            raise ValueError('must submit access_token, fb_app_namespace, fb_action_type_name')
        if not all((object_type_name, object_instance_url)):
            raise ValueError('must submit object_type_name, object_instance_url')

        url = FacebookApiUrls.graph__action_create_url(fb_graph_api=self.fb_graph_api,
                                                       fb_app_namespace=fb_app_namespace,
                                                       fb_action_type_name=fb_action_type_name,
                                                       )
        post_data = {
            'access_token': access_token,
            object_type_name: object_instance_url,
        }
        try:
            payload = self.api_proxy(url, post_data, expected_format='json.load')
            return payload
        except:
            raise

    def graph__action_list(
        self,
        access_token=None,
        fb_app_namespace=None,
        fb_action_type_name=None,
    ):
        if not all((access_token, fb_app_namespace, fb_action_type_name)):
            raise ValueError('must submit access_token, fb_app_namespace, fb_action_type_name')

        url = FacebookApiUrls.graph__action_list_url(fb_graph_api=self.fb_graph_api,
                                                     fb_app_namespace=fb_app_namespace,
                                                     fb_action_type_name=fb_action_type_name,
                                                     access_token=access_token,
                                                     )
        try:
            payload = self.api_proxy(url, expected_format='json.load')
            return payload
        except:
            raise

    def graph__action_delete(self, access_token=None, action_id=None):
        if not all((access_token, action_id)):
            raise ValueError('must submit action_id')

        url = FacebookApiUrls.graph__action_delete_url(fb_graph_api=self.fb_graph_api,
                                                       action_id=action_id,
                                                       )
        post_data = {
            'access_token': access_token,
        }
        try:
            payload = self.api_proxy(url,
                                     post_data=post_data,
                                     expected_format='json.load',
                                     is_delete=True,
                                     )
            return payload
        except:
            raise

    def verify_signed_request(self, signed_request=None, timeout=None):
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

    def __init__(
        self,
        request,
        oauth_token_redirect_uri=None,
        oauth_code_redirect_uri=None,
        fb_graph_api_version=None,
        app_secret=None,
        app_domain=None,
        ssl_verify=None,
        app_scope=None,
        app_id=None
    ):
        """
        Creates a new ``FacebookHub`` object, sets it up with Pyramid Config vars, and then proxies other functions into it.
        """
        self.request = request
        registry_settings = request.registry.settings

        if fb_graph_api_version is None and 'facebook.graph_api_version' in registry_settings:
            fb_graph_api_version = registry_settings['facebook.graph_api_version']

        if app_id is None and 'facebook.app.id' in registry_settings:
            app_id = registry_settings['facebook.app.id']
        if app_secret is None and 'facebook.app.secret' in registry_settings:
            app_secret = registry_settings['facebook.app.secret']
        if app_scope is None and 'facebook.app.scope' in registry_settings:
            app_scope = registry_settings['facebook.app.scope']
        if app_domain is None:
            app_domain = registry_settings['app_domain']
        if oauth_code_redirect_uri is None and 'facebook.app.oauth_code_redirect_uri' in registry_settings:
            oauth_code_redirect_uri = registry_settings['facebook.app.oauth_code_redirect_uri']
        if oauth_token_redirect_uri is None and 'facebook.app.oauth_token_redirect_uri' in registry_settings:
            oauth_token_redirect_uri = registry_settings['facebook.app.oauth_token_redirect_uri']
        if ssl_verify is None and 'facebook.app.ssl_verify' in registry_settings:
            ssl_verify = registry_settings['facebook.app.ssl_verify']

        FacebookHub.__init__(self,
                             app_id=app_id,
                             app_secret=app_secret,
                             app_scope=app_scope,
                             app_domain=app_domain,
                             oauth_code_redirect_uri=oauth_code_redirect_uri,
                             oauth_token_redirect_uri=oauth_token_redirect_uri,
                             ssl_verify=ssl_verify,
                             fb_grap_api_version=fb_graph_api_version,
                             )

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
