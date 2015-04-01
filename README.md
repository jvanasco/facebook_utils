facebook_utils
~~~~~~~~~~~~

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


IMPORTANT NOTE
==============

Facebook's API Support is inconsistent with the terminology:

* The API endpoints expect `client_id` and `client_secret`
* The Developer Tools provide `app id` and `app secret`

For the sake of clarity, this library uses the terms `app_id` and `app_secret` because they are what Facebook's developer dashboard provides.  They are translated into the API Endpoint terms as required.


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

it should be simple...

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