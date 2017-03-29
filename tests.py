import unittest
import os
import pdb
import pprint
import urllib

import facebook_utils as fb


class TestFacebookUtils_Authenticated(unittest.TestCase):
    FBUTILS_ACCESS_TOKEN = None

    def _newHub(self):
        """
        we need the following env variables set:
            FBUTILS_APP_ID
            FBUTILS_APP_SECRET
            FBUTILS_APP_SCOPE
            FBUTILS_APP_DOMAIN
            FBUTILS_ACCESS_TOKEN*
        This might need to be set:
            FBUTILS_APP_SECRETPROOF
            
        Note:
            *FBUTILS_ACCESS_TOKEN can be a user access token (vs an app or page token)
            we just need the ability to test some actions that require an access token.
        """
        env = os.environ
        if 'FBUTILS_APP_ID' not in os.environ:
            raise ValueError('Test must have FBUTILS_APP_ID')
        self.FBUTILS_APP_ID = os.environ['FBUTILS_APP_ID']
        if 'FBUTILS_APP_SECRET' not in os.environ:
            raise ValueError('Test must have FBUTILS_APP_SECRET')
        self.FBUTILS_APP_SECRET = os.environ['FBUTILS_APP_SECRET']
        if 'FBUTILS_APP_SCOPE' not in os.environ:
            raise ValueError('Test must have FBUTILS_APP_SCOPE')
        self.FBUTILS_APP_SCOPE = os.environ['FBUTILS_APP_SCOPE']
        if 'FBUTILS_ACCESS_TOKEN' not in os.environ:
            raise ValueError('Test must have FBUTILS_ACCESS_TOKEN')
        self.FBUTILS_ACCESS_TOKEN = os.environ['FBUTILS_ACCESS_TOKEN']
        if 'FBUTILS_APP_DOMAIN' not in os.environ:
            raise ValueError('Test must have FBUTILS_APP_DOMAIN')
        self.FBUTILS_APP_DOMAIN = os.environ['FBUTILS_APP_DOMAIN']
        self.FBUTILS_APP_SECRETPROOF = os.environ.get('FBUTILS_APP_SECRETPROOF', None)

        hub = fb.FacebookHub(app_id=self.FBUTILS_APP_ID,
                             app_secret=self.FBUTILS_APP_SECRET,
                             app_secretproof=self.FBUTILS_APP_SECRETPROOF,
                             app_scope='email',
                             app_domain=self.FBUTILS_APP_DOMAIN,
                             oauth_code_redirect_uri='https://%s/oauth-code' % self.FBUTILS_APP_DOMAIN,
                             oauth_token_redirect_uri='https://%s/oauth-token' % self.FBUTILS_APP_DOMAIN,
                             )
        return hub

    def test_oauth_code__url_dialog(self):
        hub = self._newHub()
        url = hub.oauth_code__url_dialog()
        self.assertEqual(url,
                         'https://www.facebook.com/dialog/oauth?client_id=%(FBUTILS_APP_ID)s&scope=email&redirect_uri=https%%3A%%2F%%2F%(FBUTILS_APP_DOMAIN)s%%2Foauth-code' % 
                            {'FBUTILS_APP_ID': hub.app_id,
                             'FBUTILS_APP_DOMAIN': urllib.quote_plus(self.FBUTILS_APP_DOMAIN),
                            }
                         )

    def test_oauth_code__url_dialog__custom_redirect(self):
        hub = self._newHub()
        url = hub.oauth_code__url_dialog(redirect_uri='https://%(FBUTILS_APP_DOMAIN)s/oauth-code-custom' % {'FBUTILS_APP_DOMAIN': urllib.quote_plus(self.FBUTILS_APP_DOMAIN)})
        self.assertEqual(url,
                         'https://www.facebook.com/dialog/oauth?client_id=%(FBUTILS_APP_ID)s&scope=email&redirect_uri=https%%3A%%2F%%2F%(FBUTILS_APP_DOMAIN)s%%2Foauth-code-custom' % 
                            {'FBUTILS_APP_ID': hub.app_id,
                             'FBUTILS_APP_DOMAIN': urllib.quote_plus(self.FBUTILS_APP_DOMAIN),
                            }
                         )

    def test_oauth_code__url_custom_scope(self):
        hub = self._newHub()
        url = hub.oauth_code__url_dialog(scope='email,user_birthday')
        self.assertEqual(url,
                         'https://www.facebook.com/dialog/oauth?client_id=%(FBUTILS_APP_ID)s&scope=email,user_birthday&redirect_uri=https%%3A%%2F%%2F%(FBUTILS_APP_DOMAIN)s%%2Foauth-code' % 
                            {'FBUTILS_APP_ID': hub.app_id,
                             'FBUTILS_APP_DOMAIN': urllib.quote_plus(self.FBUTILS_APP_DOMAIN),
                            }
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
        # python -munittest tests.TestFacebookUtils_Authenticated.test_access_token_exchange_manual
        hub = self._newHub()
        url_exchange = hub.oauth__url_extend_access_token(access_token=self.FBUTILS_ACCESS_TOKEN)
        fb_data = hub.api_proxy(url=url_exchange, expected_format='json.load')
        access_token = fb_data['access_token']
        self.assertTrue(access_token)

    def test_access_token_exchange_graph(self):
        hub = self._newHub()
        response = hub.graph__extend_access_token(access_token=self.FBUTILS_ACCESS_TOKEN)
        self.assertTrue(response['access_token'])

    def test_graph_me(self):
        hub = self._newHub()
        url_me = hub.graph__url_me_for_access_token(access_token=self.FBUTILS_ACCESS_TOKEN)
        fb_data = hub.api_proxy(url=url_me, expected_format='json.load')
        self.assertTrue(fb_data)

    def test_graph__get_profile_for_access_token(self):
        hub = self._newHub()
        fb_data = hub.graph__get_profile_for_access_token(access_token=self.FBUTILS_ACCESS_TOKEN)
        self.assertTrue(fb_data)

    def test_graph__get_batched(self):
        hub = self._newHub()
        FB_LIMIT_LINKS = 1
        FB_LIMIT_HOME = 1
        FB_FIELDS = 'id,from,message,comments,created_time,link,caption'
        fb_post_data = {
            'access_token': self.FBUTILS_ACCESS_TOKEN,
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


