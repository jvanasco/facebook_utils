# -*- coding: utf-8 -*-

import urllib


FB_GRAPH_API_URL = 'https://graph.facebook.com/'
FB_URL = 'https://www.facebook.com'


class FacebookApiUrls(object):

    @classmethod
    def oauth_code__url_dialog(cls, app_id, redirect_uri, scope, auth_type=''):
        auth_type = '&auth_type=%s' % auth_type if auth_type else ''
        return u'{fb_url}/dialog/oauth?client_id={app_id}&scope={scope}&redirect_uri={redirect_uri}{auth_type}'.format(fb_url=FB_URL,
                                                                                                                       app_id=app_id,
                                                                                                                       redirect_uri=urllib.quote(redirect_uri),
                                                                                                                       scope=scope,
                                                                                                                       auth_type=auth_type,
                                                                                                                       )

    @classmethod
    def oauth_code__url_access_token(cls, fb_graph_api, app_id, redirect_uri, app_secret, submitted_code):
        return u'{fb_graph_api}/oauth/access_token?client_id={app_id}&redirect_uri={redirect_uri}&client_secret={app_secret}&code={code}'.format(fb_graph_api=fb_graph_api,
                                                                                                                                                 app_id=app_id,
                                                                                                                                                 redirect_uri=urllib.quote(redirect_uri),
                                                                                                                                                 app_secret=app_secret,
                                                                                                                                                 code=submitted_code,
                                                                                                                                                 )

    @classmethod
    def oauth_token__url_dialog(cls, app_id, redirect_uri, scope, auth_type=''):
        auth_type = '&auth_type=%s' % auth_type if auth_type else ''
        return u'{fb_url}/dialog/oauth?client_id={app_id}&scope={scope}&redirect_uri={redirect_uri}&response_type=token'.format(fb_url=FB_URL,
                                                                                                                                app_id=app_id,
                                                                                                                                redirect_uri=urllib.quote(redirect_uri),
                                                                                                                                scope=scope,
                                                                                                                                auth_type=auth_type,
                                                                                                                                )

    @classmethod
    def oauth__url_extend_access_token(cls, fb_graph_api, app_id, app_secret, access_token):
        return u'{fb_graph_api}/oauth/access_token?client_id={app_id}&client_secret={app_secret}&grant_type=fb_exchange_token&fb_exchange_token={access_token}'.format(fb_graph_api=fb_graph_api,
                                                                                                                                                                       app_id=app_id,
                                                                                                                                                                       app_secret=app_secret,
                                                                                                                                                                       access_token=access_token,
                                                                                                                                                                       )

    @classmethod
    def graph__url_me_for_access_token(cls, fb_graph_api, access_token):
        return u'{fb_graph_api}/me?{access_token}'.format(fb_graph_api=fb_graph_api,
                                                          access_token=urllib.urlencode(dict(access_token=access_token)),
                                                          )

    @classmethod
    def graph__url_user_for_access_token(cls, fb_graph_api, access_token, user, action=None):
        if action is None:
            return u'{fb_graph_api}/{user}?{access_token}'.format(fb_graph_api=fb_graph_api,
                                                                  user=user,
                                                                  access_token=urllib.urlencode(dict(access_token=access_token)),
                                                                  )

        return u'{fb_graph_api}/{user}/{action}?{access_token}'.format(fb_graph_api=fb_graph_api,
                                                                       user=user,
                                                                       action=action,
                                                                       access_token=urllib.urlencode(dict(access_token=access_token)),
                                                                       )

    @classmethod
    def graph__action_create_url(cls, fb_graph_api, fb_app_namespace, fb_action_type_name):
        return u'{fb_graph_api}/me/{fb_fb_app_namespace}:{fb_action_type_name}'.format(fb_graph_api=fb_graph_api,
                                                                                       fb_app_namespace=fb_app_namespace,
                                                                                       fb_action_type_name=fb_action_type_name,
                                                                                       )

    @classmethod
    def graph__action_list_url(cls, fb_graph_api, fb_app_namespace, fb_action_type_name, access_token):
        return u'{fb_graph_api}/me/{fb_app_namespace}:{fb_action_type_name}?access_token={access_token}'.format(fb_graph_api=fb_graph_api,
                                                                                                                fb_app_namespace=fb_app_namespace,
                                                                                                                fb_action_type_name=fb_action_type_name,
                                                                                                                access_token=access_token,
                                                                                                                )

    @classmethod
    def graph__action_delete_url(cls, fb_graph_api, action_id):
        return u'{fb_graph_api}/{action_id}'.format(fb_graph_api=fb_graph_api,
                                                    action_id=action_id,
                                                    )
