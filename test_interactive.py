import facebook_utils
import os
import pdb
import pprint

# ugly python2/3
try:
    _input = raw_input
except:
    _input = input


instructions = """
make sure the app_domain is configured

    export FBUTILS_APP_ID=xxxxxxxxx
    export FBUTILS_APP_SECRET=xxxxxxxxxx
    export FBUTILS_APP_SCOPE=email,publish_actions
    export FBUTILS_APP_DOMAIN=xxxxxxxxxx
    export FBUTILS_REDIRECT_URI_OAUTHCODE=https://dev.cliqued.in/in/oauth?response_type=code'
"""

if 'FBUTILS_APP_ID' not in os.environ:
    raise ValueError('Test must have FBUTILS_APP_ID')
FBUTILS_APP_ID = os.environ['FBUTILS_APP_ID']

if 'FBUTILS_APP_SECRET' not in os.environ:
    raise ValueError('Test must have FBUTILS_APP_SECRET')
FBUTILS_APP_SECRET = os.environ['FBUTILS_APP_SECRET']

if 'FBUTILS_APP_DOMAIN' not in os.environ:
    raise ValueError('Test must have FBUTILS_APP_DOMAIN')
FBUTILS_APP_DOMAIN = os.environ['FBUTILS_APP_DOMAIN']

if 'FBUTILS_APP_SCOPE' not in os.environ:
    raise ValueError('Test must have FBUTILS_APP_SCOPE')
FBUTILS_APP_SCOPE = os.environ['FBUTILS_APP_SCOPE']

if 'FBUTILS_REDIRECT_URI_OAUTHCODE' not in os.environ:
    raise ValueError('Test must have FBUTILS_REDIRECT_URI_OAUTHCODE')
FBUTILS_REDIRECT_URI_OAUTHCODE = os.environ['FBUTILS_REDIRECT_URI_OAUTHCODE']

FBUTILS_APP_SECRETPROOF = os.environ.get('FBUTILS_APP_SECRETPROOF', None)

def new_fb_object():
    return facebook_utils.FacebookHub(
        app_id=FBUTILS_APP_ID,
        app_secret=FBUTILS_APP_SECRET,
        app_secretproof=FBUTILS_APP_SECRETPROOF,
        app_scope=FBUTILS_APP_SCOPE,
        oauth_code_redirect_uri=FBUTILS_REDIRECT_URI_OAUTHCODE,
        debug_error = True,
    )

def _get_code(_hub):
    print("Visit the following url to approve.  You will be redirected back to the `FBUTILS_REDIRECT_URI_OAUTHCODE` URI")
    print _hub.oauth_code__url_dialog()
    _code = _input("""What is the `code` in the url?""")
    _code = _code.strip()
    # remove fragments
    _code = _code.split('#')[0]
    return _code

#
# STEP 1 - generate a dialog url
#
hub = new_fb_object()

# this one is a bit extended. not always needed
if True:
    print("*" * 40)
    _code = _get_code(hub)
    print("fbutils will now try to exchange the code for an access token.")
    print("fbutils will access the facebook graph api:")
    print(hub.oauth_code__url_access_token(submitted_code=_code, redirect_uri=FBUTILS_REDIRECT_URI_OAUTHCODE, scope=FBUTILS_APP_SCOPE))
    access_token = hub.oauth_code__get_access_token(submitted_code=_code)
    print("The access token is: `%s`" % access_token)

    print("*" * 40)
    print("let's do this again, but save the full response.")
    _code = _get_code(hub)
    print(hub.oauth_code__url_access_token(submitted_code=_code, redirect_uri=FBUTILS_REDIRECT_URI_OAUTHCODE, scope=FBUTILS_APP_SCOPE))
    (access_token,
     response
     ) = hub.oauth_code__get_access_token(submitted_code=_code, keep_response=True)
    print("The access token is: `%s`" % access_token)
    print("The response is: %s" % pprint.pformat(response))

print("*" * 40)
print("now let's try to get the profile&token at once.")
_code = _get_code(hub)
(access_token,
 profile
 ) = hub.oauth_code__get_access_token_and_profile(submitted_code=_code, )
print("The access token is: `%s`" % access_token)
print("The profile is: %s" % pprint.pformat(profile))


print("*" * 40)
print("now let's grab the profile alone.")
url_me = hub.graph__url_me_for_access_token(access_token)
fb_data = hub.api_proxy(url=url_me, expected_format='json.load')
print fb_data

print("*" * 40)
print("now let's grab a batch.")
FB_LIMIT_LINKS = 1
FB_LIMIT_HOME = 1
FB_FIELDS = 'id,from,message,comments,created_time,link,caption,description'

url_multi = """https://graph.facebook.com"""
fb_post_data = {'access_token': access_token,
                'batch': [{"method": "GET", 'relative_url': "/me/permissions", },
                          {"method": "GET", 'relative_url': "/me/feed", 'limit': FB_LIMIT_LINKS, 'fields': FB_FIELDS, },
                          # {"method": "GET", 'relative_url': "/me/links", 'limit': FB_LIMIT_LINKS, 'fields': FB_FIELDS, },
                          # {"method": "GET", 'relative_url': "/me/home", 'limit': FB_LIMIT_HOME, 'fields': FB_FIELDS, },
                          ],
                }
fb_data = hub.api_proxy(url=url_multi, expected_format='json.load', post_data=fb_post_data, )
pprint.pprint(fb_data)
