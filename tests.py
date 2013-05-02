import unittest
import os

import facebook_utils as fb

class TestFacebookUtils(unittest.TestCase):

    def _newHub(self):
        env= os.environ
        if True :
            if 'PYTHON_FB_UTILS_APP_ID' not in os.environ:
                raise ValueError('Test must have PYTHON_FB_UTILS_APP_ID')
            PYTHON_FB_UTILS_APP_ID = os.environ['PYTHON_FB_UTILS_APP_ID']
            if 'PYTHON_FB_UTILS_APP_SECRET' not in os.environ:
                raise ValueError('Test must have PYTHON_FB_UTILS_APP_SECRET')
            PYTHON_FB_UTILS_APP_SECRET = os.environ['PYTHON_FB_UTILS_APP_SECRET']
        else:
            PYTHON_FB_UTILS_APP_ID= 123
            PYTHON_FB_UTILS_APP_SECRET= 123

        hub= fb.FacebookHub( app_id=PYTHON_FB_UTILS_APP_ID, app_secret=PYTHON_FB_UTILS_APP_SECRET, app_scope='email' , app_domain='127.0.0.1' , oauth_code_redirect_uri='http://127.0.0.1:5010/oauth-code', oauth_token_redirect_uri='http://127.0.0.1:5010/oauth-token' )
        return hub
        
    def test_oauth_code__url_dialog(self):
        hub= self._newHub()
        url = hub.oauth_code__url_dialog()
        self.assertEqual(url, 'https://www.facebook.com/dialog/oauth?client_id=%(PYTHON_FB_UTILS_APP_ID)s&scope=email&redirect_uri=http%%3A//127.0.0.1%%3A5010/oauth-code' % { 'PYTHON_FB_UTILS_APP_ID':hub.app_id })

    def test_oauth_code__url_dialog__custom_redirect(self):
        hub= self._newHub()
        url = hub.oauth_code__url_dialog(redirect_uri='http://127.0.0.1:5010/oauth-code-custom')
        self.assertEqual(url, 'https://www.facebook.com/dialog/oauth?client_id=%(PYTHON_FB_UTILS_APP_ID)s&scope=email&redirect_uri=http%%3A//127.0.0.1%%3A5010/oauth-code-custom'% { 'PYTHON_FB_UTILS_APP_ID':hub.app_id })

    def test_oauth_code__url_custom_scrope(self):
        hub= self._newHub()
        url = hub.oauth_code__url_dialog( scope='email,user_birthday')
        self.assertEqual(url, 'https://www.facebook.com/dialog/oauth?client_id=%(PYTHON_FB_UTILS_APP_ID)s&scope=email,user_birthday&redirect_uri=http%%3A//127.0.0.1%%3A5010/oauth-code'% { 'PYTHON_FB_UTILS_APP_ID':hub.app_id })

    def test_oauth_code__url_access_token__fails_without_code(self):
        hub= self._newHub()
        self.assertRaises(ValueError,lambda:hub.oauth_code__url_access_token())

    def test_oauth_code__get_access_token_and_profile__fails_without_code(self):
        hub= self._newHub()
        self.assertRaises(ValueError,lambda:hub.oauth_code__get_access_token_and_profile())

    def test_oauth_code__oauth_code__get_access_token__fails_without_code(self):
        hub= self._newHub()
        self.assertRaises(ValueError,lambda:hub.oauth_code__get_access_token())




