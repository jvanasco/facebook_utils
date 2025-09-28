"""
INSTRUCTIONS

This file is used to generate the test credentials

The following environment variables are required:

    export FBUTILS_APP_ID=xxxxxxxxx
    export FBUTILS_APP_SECRET=xxxxxxxxxx
    export FBUTILS_ENABLE_SECRETPROOF=1
    export FBUTILS_APP_SCOPE=email
    export FBUTILS_APP_DOMAIN=xxxxxxxxxx
    export FBUTILS_REDIRECT_URI_OAUTH_CODE=https://myapp.example.com/oauth?response_type=code'

"""

# stdlib
from typing import TYPE_CHECKING

# local
import facebook_utils
from facebook_utils.utils import parse_environ


# ==============================================================================


REQUIRED_ENV = [
    "FBUTILS_APP_ID",
    "FBUTILS_APP_SECRET",
    "FBUTILS_APP_SCOPE",
    "FBUTILS_ENABLE_SECRETPROOF",
    # "FBUTILS_APP_DOMAIN",
    "FBUTILS_REDIRECT_URI_OAUTH_CODE",
]
FB_UTILS_ENV = parse_environ(requires=REQUIRED_ENV)


# ------------------------------------------------------------------------------


def new_fb_object():

    # assured by parse_environ above
    app_id = FB_UTILS_ENV["app_id"]
    app_secret = FB_UTILS_ENV["app_secret"]
    app_scope = FB_UTILS_ENV["app_scope"]
    enable_secretproof = FB_UTILS_ENV["enable_secretproof"]
    oauth_code_redirect_uri = FB_UTILS_ENV["oauth_code_redirect_uri"]

    if TYPE_CHECKING:
        assert isinstance(app_id, str)
        assert isinstance(app_secret, str)
        assert isinstance(app_scope, str)
        assert isinstance(enable_secretproof, bool)
        assert isinstance(oauth_code_redirect_uri, str)

    return facebook_utils.FacebookHub(
        app_id=app_id,
        app_secret=app_secret,
        app_scope=app_scope,
        enable_secretproof=enable_secretproof,
        oauth_code_redirect_uri=oauth_code_redirect_uri,
        debug_error=True,
    )


def _get_code(_hub):
    print(
        "Visit the following url to approve.\n"
        "You will be redirected back to the `FBUTILS_REDIRECT_URI_OAUTH_CODE` URI.\n"
        ">>> "
    )
    print(_hub.oauth_code__url_dialog())
    _url = input("""Please copy/paste the entire URL you were redirected to >>> """)
    _code = _hub.extract__code_from_redirect(_url)
    return _code


def generate_credential():
    #
    # STEP 1 - generate a dialog url
    #
    hub = new_fb_object()
    print(("*" * 40))
    _code = _get_code(hub)
    print("fbutils will now try to exchange the code for an Access Token.")
    print(">>> fbutils will access the Facebook GraphAPI:")
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
    print("")
    print("!!! The access token is:")
    print("")
    print("----- BEGIN ACCESS TOKEN -----")
    print(access_token)
    print("----- END ACCESS TOKEN -----")
    print("")
    print("This AccessToken can now be used as an environment variable for tests.")
    print("")
    print("export FBUTILS_ACCESS_TOKEN={ACCESS_TOKEN}")


if __name__ == "__main__":
    generate_credential()
