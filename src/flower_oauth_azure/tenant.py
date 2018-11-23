import base64
import functools
import json
import os
import re
from urllib.parse import urlencode

import jwt.api_jwt as jwt
import tornado.auth
import tornado.web
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from flower.views import BaseHandler
from tornado import httpclient
from jwt import DecodeError, ExpiredSignature, decode as jwt_decode


#
# from flower.views.auth import GithubLoginHandler, GoogleAuth2LoginHandler
# a = GoogleAuth2LoginHandler
# b = GithubLoginHandler


class AzureTenantLoginHandler(BaseHandler, tornado.auth.OAuth2Mixin):
    __OAUTH_AUTHORIZE_URL = "https://login.microsoftonline.com/{tenant}/oauth2/authorize"
    __OAUTH_ACCESS_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/token"
    __JWKS_URL = 'https://login.microsoftonline.com/{tenant}/discovery/keys'
    _OAUTH_NO_CALLBACKS = True
    _OAUTH_SETTINGS_KEY = 'oauth'

    @property
    def tenant(self):
        return os.environ.get('FLOWER_OAUTH2_TENANT', 'common')

    @property
    def _OAUTH_AUTHORIZE_URL(self):
        return self.__OAUTH_AUTHORIZE_URL.format(tenant=self.tenant)

    @property
    def _JWKS_URL(self):
        return self.__JWKS_URL.format(tenant=self.tenant)

    @property
    def access_token_url(self):
        return self.__OAUTH_ACCESS_TOKEN_URL.format(tenant=self.tenant)

    @tornado.auth._auth_return_future
    def get_authenticated_user(self, redirect_uri, code, callback=None):
        http = self.get_auth_http_client()
        body = urlencode({
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": self.settings[self._OAUTH_SETTINGS_KEY]['key'],
            "client_secret": self.settings[self._OAUTH_SETTINGS_KEY]['secret'],
            "grant_type": "authorization_code",
        })
        return http.fetch(
            self.access_token_url,
            functools.partial(self._on_access_token, callback),
            method="POST",
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                     'Accept': 'application/json'}, body=body)

    @tornado.web.asynchronous
    def _on_access_token(self, future, response):
        if response.error:
            future.set_exception(tornado.auth.AuthError(
                'OAuth authentication error: %s' % str(response)))
            return

        future.set_result(json.loads(response.body.decode('utf-8')))

    def get_auth_http_client(self):
        return httpclient.AsyncHTTPClient()

    def jwt_decode_handler(self, token, key='', **kwargs):
        options = {
            'verify_exp': os.environ.get('JWT_VERIFY_EXPIRATION', '0') == '1',
        }
        # get user from token, BEFORE verification, to get user secret key
        # unverified_payload = jwt.decode(token, None, False)
        # secret_key = self.settings[self._OAUTH_SETTINGS_KEY]['secret']
        return jwt.decode(
            jwt=token,
            verify=False,
            options=options,
            **kwargs
        )

    @tornado.web.asynchronous
    def get(self):
        redirect_uri = self.settings[self._OAUTH_SETTINGS_KEY]['redirect_uri']
        if self.get_argument('code', False):
            self.get_authenticated_user(
                redirect_uri=redirect_uri,
                code=self.get_argument('code'),
                callback=self._on_auth,
            )
        else:
            self.authorize_redirect(
                redirect_uri=redirect_uri,
                client_id=self.settings[self._OAUTH_SETTINGS_KEY]['key'],
                scope=['openid', 'profile', 'user_impersonation'],
                response_type='code',
                extra_params={}
            )

    @tornado.web.asynchronous
    def _on_certificate(self, id_token, key_id, algorithm, response):
        content = json.loads(response.body)
        # find the proper key for the kid
        for key in content['keys']:
            if key['kid'] == key_id:
                x5c = key['x5c'][0]
                break
        else:
            raise DecodeError('Cannot find kid={}'.format(key_id))

        body = '-----BEGIN CERTIFICATE-----\n' \
               '{}\n' \
               '-----END CERTIFICATE-----'.format(x5c)

        certificate = load_pem_x509_certificate(body.encode(),
                                                default_backend())

        decoded = self.jwt_decode_handler(id_token, key=certificate.public_key(),
                                          algorithms=algorithm,
                                          audience=self.settings[self._OAUTH_SETTINGS_KEY]['key'])
        # decoded = jwt_decode(
        #     id_token,
        #     key=certificate.public_key(),
        #     algorithms=algorithm,
        #     audience=self.settings[self._OAUTH_SETTINGS_KEY]['key'],
        # )
        self._login(decoded)

    def _login(self, payload):
        uname = payload.get('email', payload.get('unique_name'))
        if uname and re.match(self.application.options.auth, uname):
            self.set_secure_cookie("user", str(uname))
            next_ = self.get_argument('next', '/')
            self.redirect(next_)
        else:
            message = (
                "Access denied. Please use another account or "
                "ask your admin to add your email to flower --auth."
            )
            raise tornado.web.HTTPError(403, message)

    @tornado.web.asynchronous
    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, 'OAuth authentication failed')
        id_token = user['id_token']
        jwt_header = json.loads(
            base64.b64decode(id_token.split('.', 1)[0]).decode()
        )

        if os.environ.get('FLOWER_OAUTH2_VALIDATE', '0') == '1':

            # get key id and algorithm
            key_id = jwt_header['kid']
            algorithm = jwt_header['alg']

            http = self.get_auth_http_client()
            http.fetch(self._JWKS_URL,
                       functools.partial(self._on_certificate, id_token, key_id, algorithm),
                       method='GET')
        else:
            decoded = self.jwt_decode_handler(user['id_token'])
            self._login(decoded)
