# -*- coding: utf-8 -*-

from six.moves.urllib.parse import urlencode
from six.moves.urllib.parse import quote_plus

# ==============================================================================

# https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow

FB_URL_GRAPH_API = 'https://graph.facebook.com'
FB_URL_WEB = 'https://www.facebook.com'

# ==============================================================================

URL_OAUTH_DIALOG_CODE = u'{fb_url_web}/dialog/oauth?client_id={app_id}&scope={scope}&redirect_uri={redirect_uri}{auth_type}'
URL_OAUTH_DIALOG_TOKEN = u'{fb_url_web}/dialog/oauth?client_id={app_id}&scope={scope}&redirect_uri={redirect_uri}&response_type=token'
URL_OAUTH_ACCESSTOKEN_CODE = u'{fb_url_graph_api}/oauth/access_token?client_id={app_id}&redirect_uri={redirect_uri}&client_secret={app_secret}&code={code}'
URL_OAUTH_ACCESSTOKEN_EXTEND = u'{fb_url_graph_api}/oauth/access_token?grant_type=fb_exchange_token&client_id={app_id}&client_secret={app_secret}&fb_exchange_token={access_token}'
URL_GRAPH_ME_ACCESS_TOKEN = u'{fb_url_graph_api}/me?{qs}'  # qs is likely {access_token}&{fields}
URL_GRAPH_USER_ACCESS_TOKEN = u'{fb_url_graph_api}/{user}?{qs}'  # qs is likely {access_token}&{fields}
URL_GRAPH_USER_ACTION_ACCESS_TOKEN = u'{fb_url_graph_api}/{user}/{action}?{qs}'   # qs is likely {access_token}&{fields}
URL_GRAPH_ACTION_LIST_ACCESS_TOKEN = u'{fb_url_graph_api}/me/{fb_app_namespace}:{fb_action_type_name}?access_token={access_token}'
URL_GRAPH_ACTION_CREATE = u'{fb_url_graph_api}/me/{fb_fb_app_namespace}:{fb_action_type_name}'
URL_GRAPH_ACTION_DELETE = u'{fb_url_graph_api}/{action_id}'

# ==============================================================================


def extend__appsecret_proof(url, appsecret_proof=None):
    if appsecret_proof:
        return "%s&appsecret_proof=%s" % (url, appsecret_proof)
    return url


class FacebookApiUrls(object):

    @classmethod
    def oauth_code__url_dialog(cls, fb_url_web, app_id, redirect_uri, scope, auth_type=''):
        """
        endpoint params:
        :required:
            * client_id
            * redirect_uri
        :optional:
            * state
            * response_type | code, token, code%20token, granted_scopes
            * scope
        """
        auth_type = '&auth_type=%s' % auth_type if auth_type else ''
        return URL_OAUTH_DIALOG_CODE.format(fb_url_web=fb_url_web,
                                            app_id=app_id,
                                            redirect_uri=quote_plus(redirect_uri),
                                            scope=scope or '',
                                            auth_type=auth_type,
                                            )

    @classmethod
    def oauth_token__url_dialog(cls, fb_url_web, app_id, redirect_uri, scope, auth_type=''):
        auth_type = '&auth_type=%s' % auth_type if auth_type else ''
        url = URL_OAUTH_DIALOG_TOKEN.format(fb_url_web=fb_url_web,
                                            app_id=app_id,
                                            redirect_uri=quote_plus(redirect_uri),
                                            scope=scope or '',
                                            auth_type=auth_type,
                                            )
        return url

    @classmethod
    def oauth_code__url_access_token(cls, fb_url_graph_api, app_id, redirect_uri, app_secret, submitted_code):
        url = URL_OAUTH_ACCESSTOKEN_CODE.format(fb_url_graph_api=fb_url_graph_api,
                                                app_id=app_id,
                                                redirect_uri=quote_plus(redirect_uri),
                                                app_secret=app_secret,
                                                code=submitted_code,
                                                )
        return url

    @classmethod
    def oauth__url_extend_access_token(cls, fb_url_graph_api, app_id, app_secret, access_token):
        url = URL_OAUTH_ACCESSTOKEN_EXTEND.format(fb_url_graph_api=fb_url_graph_api,
                                                  app_id=app_id,
                                                  app_secret=app_secret,
                                                  access_token=access_token,
                                                  )
        return url

    @classmethod
    def graph__url_me_for_access_token(cls, fb_url_graph_api, access_token, app_secretproof=None, fields=None):
        qs = {'access_token': access_token, }
        if fields is not None:
            qs['fields'] = fields
        qs = urlencode(qs)
        url = URL_GRAPH_ME_ACCESS_TOKEN.format(fb_url_graph_api=fb_url_graph_api,
                                               qs=qs,
                                               )
        return extend__appsecret_proof(url, app_secretproof)

    @classmethod
    def graph__action_list_url(cls, fb_url_graph_api, fb_app_namespace, fb_action_type_name, access_token, app_secretproof=None):
        url = URL_GRAPH_ACTION_LIST_ACCESS_TOKEN.format(fb_url_graph_api=fb_url_graph_api,
                                                        fb_app_namespace=fb_app_namespace,
                                                        fb_action_type_name=fb_action_type_name,
                                                        access_token=access_token,
                                                        )
        return extend__appsecret_proof(url, app_secretproof)

    @classmethod
    def graph__url_user_for_access_token(cls, fb_url_graph_api, access_token, user, action=None, app_secretproof=None, fields=None):
        qs = {'access_token': access_token, }
        if fields is not None:
            qs['fields'] = fields
        qs = urlencode(qs)
        if action is None:
            url = URL_GRAPH_USER_ACCESS_TOKEN.format(fb_url_graph_api=fb_url_graph_api,
                                                     user=user,
                                                     qs=qs,
                                                     )
        else:
            url = URL_GRAPH_USER_ACTION_ACCESS_TOKEN.format(fb_url_graph_api=fb_url_graph_api,
                                                            user=user,
                                                            action=action,
                                                            qs=qs,
                                                            )
        return extend__appsecret_proof(url, app_secretproof)

    @classmethod
    def graph__action_create_url(cls, fb_url_graph_api, fb_app_namespace, fb_action_type_name, ):
        url = URL_GRAPH_ACTION_CREATE.format(fb_url_graph_api=fb_url_graph_api,
                                             fb_app_namespace=fb_app_namespace,
                                             fb_action_type_name=fb_action_type_name,
                                             )
        return url

    @classmethod
    def graph__action_delete_url(cls, fb_url_graph_api, action_id):
        url = URL_GRAPH_ACTION_DELETE.format(fb_url_graph_api=fb_url_graph_api,
                                             action_id=action_id,
                                             )
        return url
