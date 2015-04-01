import datetime


class ApiError(Exception):

    """ Handle the facebook api errors

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
        return u'ApiError: {code} | {type} | {message}'.format(code=self.code,
                                                               type=self.type,
                                                               message=self.message,
                                                               )


class ApiAuthError(ApiError):
    """ Facebook api authentification error

    """
    pass


class ApiAuthExpiredError(ApiAuthError):
    """ Facebook api authentification error due to expiry

    """
    pass


class ApiApplicationError(ApiError):
    """ Application set up error

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
    """parses facebook's timestamp into a datetime object"""
    return datetime.datetime.strptime(fb_time, '%Y-%m-%dT%H:%M:%S+0000')
