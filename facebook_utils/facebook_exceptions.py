import datetime
from six import text_type


class ApiError(Exception):
    """
    Base class for handling the Facebook API errors.
    """

    code = None
    type = None
    message = None
    response = None
    raised = None

    def __init__(self,
                 code=None,
                 type=None,
                 message=None,
                 response=None,
                 raised=None,
                 ):
        self.code = code
        self.type = type
        self.message = message
        self.response = response
        self.raised = raised

    def __str__(self):
        return text_type('ApiError: {code} | {type} | {message}')\
            .format(code=self.code,
                    type=self.type,
                    message=self.message,
                    )


class ApiAuthError(ApiError):
    """
    Facebook api authentification error
    """
    pass


class ApiAuthExpiredError(ApiAuthError):
    """
    Facebook api authentification error due to expiry
    """
    pass


class ApiApplicationError(ApiError):
    """
    Application set up error
    """
    pass


class ApiResponseError(ApiError):
    """
    Api Response Error
    """
    pass


class ApiRuntimeError(ApiError):
    """
    Runtime Error
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


class ApiRatelimitedError(ApiError):
    """
    Raised if the application is ratelimited

    Select bits of text from Facebook's publicly shared documents are

    The following text is copyright Facebook and appears on the url:
        https://developers.facebook.com/docs/graph-api/advanced/rate-limiting/

    -- - - ---- - - ---- - - ---- - - ---- - - ---- - - ---- - - ---- - - ---- -
    All responses to calls made to the Graph API include an X-App-Usage HTTP header. This header contains the current percentage of usage for your app. This percentage is equal to the usage shown to you in the rate limiting graphs. Use this number to dynamically balance your call load to avoid being throttled.

    The rate limiting header is a JSON-formatted string in the following form:

        {
          "call_count"    : x,
          "total_time"    : y,
          "total_cputime" : z
        }

    The values for x, y and z are whole numbers representing the percentage used values for each of the metrics. When any of these metrics exceed 100 the app is rate limited.

    What Errors Will My App See?

    Throttling Type	                At least	                Error Code
    Application-level throttling    200 calls/person/hour       4
    Account-level throttling        Not applicable              17
    Page-level throttling           4800 calls/person/24-hours  32
    Custom-level throttling         Not applicable              613

    -- - - ---- - - ---- - - ---- - - ---- - - ---- - - ---- - - ---- - - ---- -

    From Facebook's Application Dashboard, also copyright Facebook:

    Rate limiting defines limits on how many API calls can be made within a specified time period. Application-level rate limits apply to calls made using any access token other than a Page access token and ads APIs calls. The total number of calls your app can make per hour is 200 times the number of users. Please note this isn't a per-user limit. Any individual user can make more than 200 calls per hour, as long as the total for all users does not exceed the app maximum.
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

    def __str__(self):
        return "ApiError: %s " % (self.raised)


class AuthenticatedHubRequired(Exception):
    """
    raised when an unauthenticated hub tries to perform an authenticated function
    """
    pass


def reformat_error(json_string, raised=None):

    rval = {'message': None,
            'type': None,
            'code': None,
            'raised': None
            }

    for k in rval.keys():
        if k in json_string:
            rval[k] = json_string[k]
    if raised is not None:
        rval['raised'] = raised
    return rval


def facebook_time(fb_time):
    """parses Facebook's timestamp into a datetime object"""
    return datetime.datetime.strptime(fb_time, '%Y-%m-%dT%H:%M:%S+0000')
