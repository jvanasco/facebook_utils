"""
INSTRUCTIONS

This tests requires AT LEAST the following set

    export FBUTILS_APP_ID=xxxxxxxxx
    export FBUTILS_APP_SECRET=xxxxxxxxxx
    export FBUTILS_ENABLE_SECRETPROOF=1
    export FBUTILS_APP_SCOPE=email
    export FBUTILS_APP_DOMAIN=xxxxxxxxxx
    export FBUTILS_REDIRECT_URI_OAUTH_CODE=https://myapp.example.com/oauth?response_type=code'

"""

# stdlib
import os
import pprint

# local
import facebook_utils
from facebook_utils.utils import parse_environ


# ==============================================================================


REQUIRED_ENV = [
    "FBUTILS_APP_ID",
    "FBUTILS_APP_SECRET",
    "FBUTILS_ENABLE_SECRETPROOF",
    "FBUTILS_APP_DOMAIN",
    "FBUTILS_APP_SCOPE",
    "FBUTILS_REDIRECT_URI_OAUTH_CODE",
]
FB_UTILS_ENV = parse_environ(requires=REQUIRED_ENV)

# ------------------------------------------------------------------------------


def new_fb_object():
    return facebook_utils.FacebookHub(
        app_id=FB_UTILS_ENV["app_id"],
        app_secret=FB_UTILS_ENV["app_secret"],
        app_scope=FB_UTILS_ENV["app_scope"],
        enable_secretproof=FB_UTILS_ENV["enable_secretproof"],
        oauth_code_redirect_uri=FB_UTILS_ENV["oauth_code_redirect_uri"],
        debug_error=True,
    )


def _get_code(_hub):
    print(
        "Visit the following url to approve. You will be redirected back to the `FBUTILS_REDIRECT_URI_OAUTH_CODE` URI >>> "
    )
    print(_hub.oauth_code__url_dialog())
    _url = input("""Please copy/paste the entire URL you were redirected to >>> """)
    _code = _hub.extract__code_from_redirect(_url)
    return _code


#
# STEP 1 - generate a dialog url
#
hub = new_fb_object()

if not FB_UTILS_ENV["access_token"]:

    # this one is a bit extended. not always needed
    if os.environ.get("FBUTILS_TEST_EXTENDED"):

        print(("*" * 40))
        _code = _get_code(hub)
        print("fbutils will now try to exchange the code for an access token.")
        print(">>> fbutils will access the facebook graph api:")
        print(
            hub.oauth_code__url_access_token(
                submitted_code=_code,
                redirect_uri=FB_UTILS_ENV["oauth_code_redirect_uri"],
                scope=FB_UTILS_ENV["app_scope"],
            )
        )
        access_token = hub.oauth_code__get_access_token(submitted_code=_code)
        print("- " * 20)
        print("Success!")
        print("!!! The access token is: `%s`" % access_token)

        print(("*" * 40))
        print(
            "let's do this again, but use another API tool that will save the full response."
        )
        _code = _get_code(hub)
        print(
            hub.oauth_code__url_access_token(
                submitted_code=_code,
                redirect_uri=FB_UTILS_ENV["oauth_code_redirect_uri"],
                scope=FB_UTILS_ENV["app_scope"],
            )
        )
        (access_token, response) = hub.oauth_code__get_access_token(
            submitted_code=_code, keep_response=True
        )
        print("- " * 20)
        print("Success!")
        print("!!! The access token is: `%s`" % access_token)
        print("!!! The response is: %s" % pprint.pformat(response))

    print(("*" * 40))
    print("now let's try to get the Profile & Token at once.")
    _code = _get_code(hub)
    (access_token, profile) = hub.oauth_code__get_access_token_and_profile(
        submitted_code=_code
    )
    print("- " * 20)
    print("Success!")
    print("!!! The access token is: `%s`" % access_token)
    print(">>> The profile is: %s" % pprint.pformat(profile))

else:
    print("Using ENV access token!")
    access_token = FB_UTILS_ENV["access_token"]
    print("!!! The access token is: `%s`" % access_token)


print(("*" * 40))
print("now let's grab the profile alone.")
url_me = hub.graph__url_me_for_access_token(access_token)
fb_data = hub.api_proxy(url=url_me, expected_format="json.load")
print("- " * 20)
print("Success!")
print(">>>", fb_data)

print(("*" * 40))
print("now let's grab a batch.")
FB_LIMIT_LINKS = 1
FB_LIMIT_HOME = 1
FB_FIELDS = "id,from,message,comments,created_time,link,caption,description"

url_multi = """https://graph.facebook.com"""
fb_post_data = {
    "access_token": access_token,
    "batch": [
        {"method": "GET", "relative_url": "/me/permissions"},
        {
            "method": "GET",
            "relative_url": "/me/feed",
            "limit": FB_LIMIT_LINKS,
            "fields": FB_FIELDS,
        },
        # {"method": "GET", 'relative_url': "/me/links", 'limit': FB_LIMIT_LINKS, 'fields': FB_FIELDS, },
        # {"method": "GET", 'relative_url': "/me/home", 'limit': FB_LIMIT_HOME, 'fields': FB_FIELDS, },
    ],
}
fb_data = hub.api_proxy(
    url=url_multi, expected_format="json.load", post_data=fb_post_data
)
print("- " * 20)
print("Success!")
pprint.pprint(fb_data)
