facebook_utils
~~~~~~~~~~~~

A collection of utilities for integrating user accounts with Facebook.com.

Right now this handles oAuth login and Graph API operations

This has been a general-purpose Python client for several years. It works well.

Purpose
=======

1. Once upon a time, Facebook offered a Python SDK. They dropped it. Boo.

2. When this was first released, there were no other Python SDKs actively developed.

3. There are a handful of Pyramid/Misc Framework utilities that provide a complete
drop-in integration with Facebook.com for account logins and integrations;
This is NOT one of them. Sometimes you need to control the User Experience and
have all your UX customized; if so, this is for you.


Usage
=====


All work is done via the `facebook_utils.core.FacebookHub()` object.

Configure a hub with something like the following:

	from facebook_utils import FacebookHub
    hub = FacebookHub(app_id = x,
                      app_secret = y,
                      app_secretproof = True
                      )

Or make it unuthenticated. It's up to you.


This was originally built/intended for use under the Pyramid environment.

calling `FacebookPyramid()` will create a new object that subclasses
`FacebookHub()` objects, using  default settings from your .ini and
pulling variables from 'request' as needed.

As of v0.5.0 it supports the `appsecret_proof` lockdown on the client level.

Any requests to the hub will attempt to create the `appsecret_proof` hmac if it
is not explicitly provided. It will be based on the `access_token` appearing as
(in the order of precedence):

* the `access_token` kwarg to the `.api_proxy() method
* an `access_token` in the querystring of a retrieved url
* an `access_token` in the POST payload

This will allow you to follow paginated links from the API as-is, upgrading as
needed.


IMPORTANT NOTES
===============

Facebook's API Support is inconsistent with the terminology:

* The API endpoints expect `client_id` and `client_secret`
* The Developer Tools provide `app id` and `app secret`

For the sake of clarity, this library uses the terms `app_id` and `app_secret`
because they are what Facebook's developer dashboard provides. They are translated
into the API Endpoint terms as required.

By default the API calls will be unversioned. You should specify the API version.


Supports Two oAuth Flows
=========================

Flow 1 - Server Side
--------------------
1. configure an object with `oauth_code_redirect_uri`
2. consumers click a button on your site, which redirects to
`oauth_code_redirect_uri` -- as provided by `oauth_code__url_dialog()`
3. upon success, users are redirected from Facebook to
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
3. upon success, users are redirected from Facebook to
`oauth_token__url_dialog` along with a query param titled `token` and a
hash value titled `#access_token`. The `access_token` is not visible to
the server, and must be transferred to your server via JavaScript or
not-at-all should you simply want to do all your integration in JavaScript.
4. profile data can be obtained with `.graph__get_profile(access_token)`
if you store the access token


Unauthenticated Queries
=========================

Queries without authentication required can be performed using the `.api_proxy`
method.

If you don't have any authentication data, you can create an unauthenticated
hub, which allows you to leverage this library for streamlined requests and
response processing.

    hub = FacebookHub(unauthenticated_hub=True)
    get_data = {'ids': "http://example.com", }
    fb_data = hub.api_proxy(url="""https://graph.facebook.com""",
        expected_format='json.load', get_data=get_data)
    pprint.pprint(fb_data)


Rate Limiting?
=========================

Facebook may ratelimit requests.

* see https://developers.facebook.com/docs/graph-api/advanced/rate-limiting

The last response is stored `FacebookHub._last_response` for inspection.

A convenience method will check for the `X-Page-Usage` ratelimiting header:

    print hub.last_response_ratelimited()

If no ratelimiting is set, it will return None.

If Facebook has set ratelimiting, it will convert the JSON-formatted string in
the header into a python dict:

    print hub.last_response_ratelimited()
    > {"call_count"    : x,
       "total_time"    : y,
       "total_cputime" : z
       }


Some Notes
==========

Most methods will let you override the 'scope' and 'request_uri'.
This shouldn't really be necessary and will probably be deprecated.

Some methods support multiple ways of parsing results.
Until recently, Facebook's API returned values either as url-encoded strings or
as JSON. Now most results are in JSON.


Pyramid Examples
================
define some variables in your .ini files:

file: development.ini

    # the default prefix is fbutils
    fbutils.id = 123
    fbutils.secret = 123
    fbutils.scope = email, user_birthday, user_checkins, offline_access
    fbutils.oauth_code_redirect_uri = http://127.0.0.1:5010/facebook-oauth-redirect
    fbutils.api_version = v2.8
    fbutils.oauth_code_redirect_uri=  http://127.0.0.1:5010/account/facebook-authenticate-oauth?response_type=code
    fbutils.oauth_token_redirect_uri= http://127.0.0.1:5010/account/facebook-authenticate-oauth-token?response_type=token

or:

    # customize the prefix!
    fbutils.prefix = facebook.app
    facebook.app.id = 123
    facebook.app.secret = 123
    facebook.app.secretproof = True
    facebook.app.scope = email, user_birthday, user_checkins, offline_access
    facebook.app.oauth_code_redirect_uri = http://127.0.0.1:5010/facebook-oauth-redirect
    facebook.app.api_version = v2.8
    facebook.app.oauth_code_redirect_uri=  http://127.0.0.1:5010/account/facebook-authenticate-oauth?response_type=code
    facebook.app.oauth_token_redirect_uri= http://127.0.0.1:5010/account/facebook-authenticate-oauth-token?response_type=token



Make sure your endpoints are allowlisted on the Facebook console

integrate into your handlers:

    from facebook_utils import FacebookPyramid

    class WebAccount(base.Handler):
        def __new_fb_object(self):
            "Create a new Facebook Object
             note that we can override settings in the .ini files if we want
            "
            fb = FacebookPyramid(self.request,
                                 oauth_code_redirect_uri = self.request.registry.settings['facebook.app.oauth_code_redirect_uri'],
                                 oauth_token_redirect_uri = self.request.registry.settings['facebook.app.oauth_token_redirect_uri'],
                                 )
            return fb

        def sign_up(self):
            "sign up page, which contains a "signup with facebook link"
            fb = self.__new_fb_object()
            return {"project":"MyApp", 'facebook_pyramid':facebook}

        @action(renderer="web/account/facebook_authenticate_oauth.html")
        def facebook_authenticate_oauth(self):
            fb = self.__new_fb_object()
            (access_token,
             profile
             )= fb.oauth_code__get_access_token_and_profile(self.request)
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
return json data, others return urlquoted data. `api_proxy` doesn't care.
it returns a dict from every endpoint, and does the conversion for you.

The `api_proxy` defaults to a json load. certain api calls will pass in
a different `expected_format` argument. The proxy will also handle 'batch'
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
    AuthenticatedHubRequired

`ApiError` instances contain:
    code (Facebook specific, not http code)
    type (as dictacted by Facebook)
    message (possibly dictated by Facebook)
    raised (the trapped error that raised this, if available)
    response (the repsonse in error, if available)

`AuthenticatedHubRequired` will be raised if a non-authenticated hub tries to
perform authenticated actions

The `api_proxy` will catch *most* errors. Since this is in development,
i'm raising uncaught exceptions. There will be a future "ApiUnhandledError"


Testing
===========


Trial Run
----------

1. Set up an App on https://developers.facebook.com

2. You need this information exported in your environment

	FBUTILS_APP_ID : The numeric ID for the app
	FBUTILS_APP_SECRET : You generate this on the Facebook Settings
	FBUTILS_APP_SECRETPROOF=1 : 
	FBUTILS_APP_DOMAIN : the app's domain. example: dev.example.com
	FBUTILS_APP_SCOPE : The scope. can just be "email"
	FBUTILS_REDIRECT_URI_OAUTHCODE : the uri to redirect visitors to.
		this MUST be whitelisted on Facebook's OAuth/Login settings

3. Run 

	python test-interactive.py
	
You will see a message like:

    Visit the following url to approve.  You will be redirected back to the `FBUTILS_REDIRECT_URI_OAUTHCODE` URI
https://www.facebook.com/dialog/oauth?client_id={XXXXX}&scope={XXXXX}&redirect_uri={XXXXX}

Copy/paste that url into a browser window

You will be redirected to a url like:

	{{https://dev.cliqued.in/account/login/facebook-oauth?response_type=code}}&code={{CODE}}#_=_

Copy the entire `CODE` from the URL and paste it in.  It is okay to leave the
trailing `#_=_` fragment

This will step you through multiple API calls, asking you to visit the
authorization URL each time.  

You should notice the authorization code changes each time, however the Facebook
API token which is returned will remain the same.


Unit Tests
----------

Unit Tests require the following environment vars to be set:

    FBUTILS_APP_ID
    FBUTILS_APP_SECRET
    FBUTILS_APP_SECRETPROOF
    FBUTILS_APP_SCOPE
    FBUTILS_ACCESS_TOKEN
    FBUTILS_APP_DOMAIN

it should be simple...

    export FBUTILS_APP_ID="app_id_from_facebook.com"
    export FBUTILS_APP_SECRET="app_secret_from_facebook.com"
    export FBUTILS_APP_SECRETPROOF=set if you locked this down on facebook
    export FBUTILS_APP_SCOPE="email,user_activities,user_status,user_posts"
    export FBUTILS_APP_DOMAIN='allowlisted domain'
    export FBUTILS_REDIRECT_URI_OAUTHCODE= configured on the facebook dashboard
    export FBUTILS_ACCESS_TOKEN="from_API_operations, or generate via developer interface"


To generate a `FBUTILS_ACCESS_TOKEN` value, you can use the `tests/generate_credentials.py`
script.



Integrated Tests
----------------

There is also a `test_interactive.py` file that uses the same environment vars

    python test_interactive.py

That will allow you to step through a few scenarios and set up an integration
with Facebook itself.


:copyright: 2012-2021 by Jonathan Vanasco
license: BSD
