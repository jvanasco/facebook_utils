import unittest
import os
import pdb

import facebook_utils as fb


class TestFacebookUtils_Authenticated(unittest.TestCase):
    PYTHON_FB_UTILS_ACCESS_TOKEN = None

    def _newHub(self):
        """
            we need the following env variables set:
                PYTHON_FB_UTILS_APP_ID
                PYTHON_FB_UTILS_APP_SECRET
                PYTHON_FB_UTILS_APP_SCOPE
                PYTHON_FB_UTILS_ACCESS_TOKEN
        """
        env = os.environ
        if 'PYTHON_FB_UTILS_APP_ID' not in os.environ:
            raise ValueError('Test must have PYTHON_FB_UTILS_APP_ID')
        PYTHON_FB_UTILS_APP_ID = os.environ['PYTHON_FB_UTILS_APP_ID']
        if 'PYTHON_FB_UTILS_APP_SECRET' not in os.environ:
            raise ValueError('Test must have PYTHON_FB_UTILS_APP_SECRET')
        PYTHON_FB_UTILS_APP_SECRET = os.environ['PYTHON_FB_UTILS_APP_SECRET']
        if 'PYTHON_FB_UTILS_APP_SCOPE' not in os.environ:
            raise ValueError('Test must have PYTHON_FB_UTILS_APP_SCOPE')
        PYTHON_FB_UTILS_APP_SCOPE = os.environ['PYTHON_FB_UTILS_APP_SCOPE']
        if 'PYTHON_FB_UTILS_ACCESS_TOKEN' not in os.environ:
            raise ValueError('Test must have PYTHON_FB_UTILS_ACCESS_TOKEN')
        self.PYTHON_FB_UTILS_ACCESS_TOKEN = os.environ['PYTHON_FB_UTILS_ACCESS_TOKEN']

        hub = fb.FacebookHub(app_id=PYTHON_FB_UTILS_APP_ID,
                             app_secret=PYTHON_FB_UTILS_APP_SECRET,
                             app_scope='email',
                             app_domain='127.0.0.1',
                             oauth_code_redirect_uri='http://127.0.0.1:5010/oauth-code',
                             oauth_token_redirect_uri='http://127.0.0.1:5010/oauth-token'
                             )
        return hub

    def test_oauth_code__url_dialog(self):
        hub = self._newHub()
        url = hub.oauth_code__url_dialog()
        self.assertEqual(url,
                         'https://www.facebook.com/dialog/oauth?client_id=%(PYTHON_FB_UTILS_APP_ID)s&scope=email&redirect_uri=http%%3A//127.0.0.1%%3A5010/oauth-code' % {'PYTHON_FB_UTILS_APP_ID': hub.app_id}
                         )

    def test_oauth_code__url_dialog__custom_redirect(self):
        hub = self._newHub()
        url = hub.oauth_code__url_dialog(redirect_uri='http://127.0.0.1:5010/oauth-code-custom')
        self.assertEqual(url,
                         'https://www.facebook.com/dialog/oauth?client_id=%(PYTHON_FB_UTILS_APP_ID)s&scope=email&redirect_uri=http%%3A//127.0.0.1%%3A5010/oauth-code-custom' % {'PYTHON_FB_UTILS_APP_ID': hub.app_id}
                         )

    def test_oauth_code__url_custom_scrope(self):
        hub = self._newHub()
        url = hub.oauth_code__url_dialog(scope='email,user_birthday')
        self.assertEqual(url,
                         'https://www.facebook.com/dialog/oauth?client_id=%(PYTHON_FB_UTILS_APP_ID)s&scope=email,user_birthday&redirect_uri=http%%3A//127.0.0.1%%3A5010/oauth-code' % {'PYTHON_FB_UTILS_APP_ID': hub.app_id}
                         )

    def test_oauth_code__url_access_token__fails_without_code(self):
        hub = self._newHub()
        self.assertRaises(ValueError, lambda: hub.oauth_code__url_access_token())

    def test_oauth_code__get_access_token_and_profile__fails_without_code(self):
        hub = self._newHub()
        self.assertRaises(ValueError, lambda: hub.oauth_code__get_access_token_and_profile())

    def test_oauth_code__oauth_code__get_access_token__fails_without_code(self):
        hub = self._newHub()
        self.assertRaises(ValueError, lambda: hub.oauth_code__get_access_token())

    def test_access_token_exchange_manual(self):
        hub = self._newHub()
        url_exchange = hub.oauth__url_extend_access_token(access_token=self.PYTHON_FB_UTILS_ACCESS_TOKEN)
        fb_data = hub.api_proxy(url=url_exchange, expected_format='urlparse.parse_qs')
        access_token = fb_data['access_token']
        self.assertTrue(access_token)

    def test_access_token_exchange_graph(self):
        hub = self._newHub()
        response = hub.graph__extend_access_token(access_token=self.PYTHON_FB_UTILS_ACCESS_TOKEN)
        self.assertTrue(response['access_token'])

    def test_graph_me(self):
        hub = self._newHub()
        url_me = hub.graph__url_me_for_access_token(access_token=self.PYTHON_FB_UTILS_ACCESS_TOKEN)
        fb_data = hub.api_proxy(url=url_me, expected_format='json.load')
        self.assertTrue(fb_data)

    def test_graph__get_profile_for_access_token(self):
        hub = self._newHub()
        fb_data = hub.graph__get_profile_for_access_token(access_token=self.PYTHON_FB_UTILS_ACCESS_TOKEN)
        self.assertTrue(fb_data)

    def test_graph__get_batched(self):
        hub = self._newHub()
        FB_LIMIT_LINKS = 1
        FB_LIMIT_HOME = 1
        FB_FIELDS = 'id,from,message,comments,created_time,link,caption'
        fb_post_data = {
            'access_token': self.PYTHON_FB_UTILS_ACCESS_TOKEN,
            'batch': [
                {"method": "GET", 'relative_url': "/me/permissions", },
                {"method": "GET", 'relative_url': "/me/links", 'limit': FB_LIMIT_LINKS, 'fields': FB_FIELDS, },
                {"method": "GET", 'relative_url': "/me/home", 'limit': FB_LIMIT_HOME, 'fields': FB_FIELDS, },
            ],
        }
        fb_data = hub.api_proxy(url="""https://graph.facebook.com""", expected_format='json.load', post_data=fb_post_data)
        self.assertTrue(fb_data)


class TestFacebookUtils_UnAuthenticated(unittest.TestCase):

    def _newHub(self):
        """
        this is for unauthenticated tests
        """
        env = os.environ
        hub = fb.FacebookHub(unauthenticated_hub=True)
        return hub
    
    def test_graph__get_object_single(self):
        urls = {'https://example.com': '482839044422',
                }
        url = urls.keys()[0]
        hub = self._newHub()
        get_data = {'ids': url,
                    }
        fb_data = hub.api_proxy(url="""https://graph.facebook.com""", expected_format='json.load', get_data=get_data)
        self.assertIn(url, fb_data)
        self.assertIn('og_object', fb_data[url])
        self.assertIn('id', fb_data[url]['og_object'])
        self.assertEquals(fb_data[url]['og_object']['id'], urls[url])
        
        # make sure we tracked a _last_response
        self.assertTrue(hub._last_response)
        self.assertIsNone(hub.last_response_ratelimited())

    def test_graph__get_object_multiple(self):
        # url: facebook opengraph id
        urls = {'http://example.com': '395320319544',
                'https://example.com': '482839044422',
                'http://facebook.com': '10151063484068358',
                'https://facebook.com': '10151063484068358',
                }
        hub = self._newHub()
        get_data = {'ids': ','.join(urls.keys()),
                    }
        fb_data = hub.api_proxy(url="""https://graph.facebook.com""", expected_format='json.load', get_data=get_data)
        for url in urls.keys():
            self.assertIn(url, fb_data)
            self.assertIn('og_object', fb_data[url])
            self.assertIn('id', fb_data[url]['og_object'])
            self.assertEquals(fb_data[url]['og_object']['id'], urls[url])


