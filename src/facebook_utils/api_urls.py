# -*- coding: utf-8 -*-

from typing import Optional
from urllib.parse import quote_plus
from urllib.parse import urlencode

# ==============================================================================

# https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow

FB_URL_GRAPH_API = "https://graph.facebook.com"
FB_URL_WEB = "https://www.facebook.com"

# ------------------------------------------------------------------------------

URL_OAUTH_DIALOG_CODE = "{fb_url_web}/dialog/oauth?client_id={app_id}&scope={scope}&redirect_uri={redirect_uri}{auth_type}"
URL_OAUTH_DIALOG_TOKEN = "{fb_url_web}/dialog/oauth?client_id={app_id}&scope={scope}&redirect_uri={redirect_uri}&response_type=token"
URL_OAUTH_ACCESSTOKEN_CODE = "{fb_url_graph_api}/oauth/access_token?client_id={app_id}&redirect_uri={redirect_uri}&client_secret={app_secret}&code={code}"
URL_OAUTH_ACCESSTOKEN_EXTEND = "{fb_url_graph_api}/oauth/access_token?grant_type=fb_exchange_token&client_id={app_id}&client_secret={app_secret}&fb_exchange_token={access_token}"
URL_GRAPH_ME_ACCESS_TOKEN = (
    "{fb_url_graph_api}/me?{qs}"  # qs is likely {access_token}&{fields}
)
URL_GRAPH_USER_ACCESS_TOKEN = (
    "{fb_url_graph_api}/{user}?{qs}"  # qs is likely {access_token}&{fields}
)
URL_GRAPH_USER_ACTION_ACCESS_TOKEN = (
    "{fb_url_graph_api}/{user}/{action}?{qs}"  # qs is likely {access_token}&{fields}
)
URL_GRAPH_ACTION_LIST_ACCESS_TOKEN = "{fb_url_graph_api}/me/{fb_app_namespace}:{fb_action_type_name}?access_token={access_token}"
URL_GRAPH_ACTION_CREATE = (
    "{fb_url_graph_api}/me/{fb_fb_app_namespace}:{fb_action_type_name}"
)
URL_GRAPH_ACTION_DELETE = "{fb_url_graph_api}/{action_id}"

# ------------------------------------------------------------------------------


def extend__appsecret_proof(
    url: str,
    appsecret_proof: Optional[str] = None,
) -> str:
    if appsecret_proof:
        return "%s&appsecret_proof=%s" % (url, appsecret_proof)
    return url


class FacebookApiUrls(object):
    @classmethod
    def oauth_code__url_dialog(
        cls,
        fb_url_web: Optional[str] = None,
        app_id: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        auth_type: Optional[str] = None,
    ) -> str:
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
        auth_type = "&auth_type=%s" % auth_type if auth_type else ""
        return URL_OAUTH_DIALOG_CODE.format(
            fb_url_web=fb_url_web or "",
            app_id=app_id or "",
            redirect_uri=quote_plus(redirect_uri or ""),
            scope=scope or "",
            auth_type=auth_type or "",
        )

    @classmethod
    def oauth_token__url_dialog(
        cls,
        fb_url_web: Optional[str] = None,
        app_id: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        auth_type: Optional[str] = None,
    ) -> str:
        auth_type = "&auth_type=%s" % auth_type if auth_type else ""
        url = URL_OAUTH_DIALOG_TOKEN.format(
            fb_url_web=fb_url_web or "",
            app_id=app_id or "",
            redirect_uri=quote_plus(redirect_uri or ""),
            scope=scope or "",
            auth_type=auth_type or "",
        )
        return url

    @classmethod
    def oauth_code__url_access_token(
        cls,
        fb_url_graph_api: Optional[str] = None,
        app_id: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        app_secret: Optional[str] = None,
        submitted_code: Optional[str] = None,
    ) -> str:
        url = URL_OAUTH_ACCESSTOKEN_CODE.format(
            fb_url_graph_api=fb_url_graph_api or "",
            app_id=app_id or "",
            redirect_uri=quote_plus(redirect_uri or ""),
            app_secret=app_secret or "",
            code=submitted_code or "",
        )
        return url

    @classmethod
    def oauth__url_extend_access_token(
        cls,
        fb_url_graph_api: Optional[str] = None,
        app_id: Optional[str] = None,
        app_secret: Optional[str] = None,
        access_token: Optional[str] = None,
    ) -> str:
        url = URL_OAUTH_ACCESSTOKEN_EXTEND.format(
            fb_url_graph_api=fb_url_graph_api or "",
            app_id=app_id or "",
            app_secret=app_secret or "",
            access_token=access_token or "",
        )
        return url

    @classmethod
    def graph__url_me_for_access_token(
        cls,
        fb_url_graph_api: Optional[str] = None,
        access_token: Optional[str] = None,
        app_secretproof: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> str:
        _qs = {"access_token": access_token or ""}
        if fields is not None:
            _qs["fields"] = fields
        qs = urlencode(_qs)
        url = URL_GRAPH_ME_ACCESS_TOKEN.format(
            fb_url_graph_api=fb_url_graph_api or "",
            qs=qs,
        )
        return extend__appsecret_proof(url, app_secretproof)

    @classmethod
    def graph__action_list_url(
        cls,
        fb_url_graph_api: Optional[str] = None,
        fb_app_namespace: Optional[str] = None,
        fb_action_type_name: Optional[str] = None,
        access_token: Optional[str] = None,
        app_secretproof: Optional[str] = None,
    ) -> str:
        url = URL_GRAPH_ACTION_LIST_ACCESS_TOKEN.format(
            fb_url_graph_api=fb_url_graph_api or "",
            fb_app_namespace=fb_app_namespace or "",
            fb_action_type_name=fb_action_type_name or "",
            access_token=access_token or "",
        )
        return extend__appsecret_proof(url, app_secretproof)

    @classmethod
    def graph__url_user_for_access_token(
        cls,
        fb_url_graph_api: str,
        access_token: str,
        user: str,
        action: Optional[str] = None,
        app_secretproof: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> str:
        _qs = {"access_token": access_token}
        if fields is not None:
            _qs["fields"] = fields
        qs = urlencode(_qs)
        if action is None:
            url = URL_GRAPH_USER_ACCESS_TOKEN.format(
                fb_url_graph_api=fb_url_graph_api, user=user, qs=qs
            )
        else:
            url = URL_GRAPH_USER_ACTION_ACCESS_TOKEN.format(
                fb_url_graph_api=fb_url_graph_api, user=user, action=action, qs=qs
            )
        return extend__appsecret_proof(url, app_secretproof)

    @classmethod
    def graph__action_create_url(
        cls,
        fb_url_graph_api: str,
        fb_app_namespace: str,
        fb_action_type_name: str,
    ) -> str:
        url = URL_GRAPH_ACTION_CREATE.format(
            fb_url_graph_api=fb_url_graph_api,
            fb_app_namespace=fb_app_namespace,
            fb_action_type_name=fb_action_type_name,
        )
        return url

    @classmethod
    def graph__action_delete_url(
        cls,
        fb_url_graph_api: str,
        action_id: str,
    ) -> str:
        url = URL_GRAPH_ACTION_DELETE.format(
            fb_url_graph_api=fb_url_graph_api, action_id=action_id
        )
        return url
