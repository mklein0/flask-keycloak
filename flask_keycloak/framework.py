import typing as t_
import time
import json
import os

import certifi
import flask
import flask_login
import requests

from authlib.integrations.flask_client import OAuth, OAuthError
from authlib.oauth2.rfc6749 import OAuth2Token

# from authlib.integrations.flask_client import token_update

print("Using cacerts from " + certifi.where())

app = flask.Flask('flask_keycloak')
app.secret_key = '!secret'

issuer = os.getenv('ISSUER', 'https://id.acme.test:8443/auth/realms/acme-demo')
clientId = os.getenv('CLIENT_ID', 'flask-webapp')
clientSecret = os.getenv('CLIENT_SECRET', 'lkkoQDUdJUqYDHXZBVDodw2ocvqJEflP')
oidcDiscoveryUrl = f'{issuer}/.well-known/openid-configuration'


# We do not handle OAuth2 tokens separate from authentication server, so no need to hold them
# beyond the flask.session.

# def update_token(
#         name,
#         token,
#         refresh_token=None,
#         access_token=None
# ):
#     if refresh_token:
#         item = OAuth2Token.find(name=name, refresh_token=refresh_token)
#     elif access_token:
#         item = OAuth2Token.find(name=name, access_token=access_token)
#     else:
#         return
#
#     # update old token
#     item.access_token = token['access_token']
#     item.refresh_token = token.get('refresh_token')
#     item.expires_at = token['expires_at']
#     item.save()

def clear_session():
    # type: (...) -> None
    flask.session.pop('id_token', None)
    flask.session.pop('oa_token', None)


class FlaskLoginAuthLibUser(flask_login.UserMixin):
    def __init__(
            self,
            user_info  # type: dict
    ):
        # type: (...) -> None
        """
        :param user_info: ID Token following specification:
            https://openid.net/specs/openid-connect-core-1_0.html#IDToken
        """
        # Convert identifier of OAuth Identity to a unique id string excluding session/client info.
        self.user_info = user_info
        self.id = json.dumps(
            {
                'iss': user_info['iss'],
                'sub': user_info['sub'],
            },
            sort_keys=True, indent=0
        )

    @property
    def access_token(self):
        # type: (...) -> str
        """
        Login Manager should have validated access token, so just get it from the User Session.
        """
        return flask.session['oa_token']['access_token']

    @property
    def oauth_token(self):
        # type: (...) -> OAuth2Token
        """
        Login Manager should have validated access token, so just get it from the User Session.
        """
        return OAuth2Token(flask.session['oa_token'])


class FlaskAuthLibLoginManager(flask_login.LoginManager):

    def __init__(self, app=None, add_context_processor=True):
        super().__init__(app, add_context_processor=add_context_processor)

        self.oauth_service = OAuth(
            app=app,
            # update_token=update_token,
        )
        self.oauth_service.register(
            name='keycloak',
            client_id=clientId,
            client_secret=clientSecret,
            server_metadata_url=oidcDiscoveryUrl,
            client_kwargs={
                'scope': 'openid email profile',
                'code_challenge_method': 'S256'  # enable PKCE
            },
        )
        self.request_loader(self.keycloak_load_request)

    def keycloak_load_request(
            self,
            request  # type: flask.Request
    ):
        # type: (...) -> t_.Optional[flask_login.UserMixin]
        access_token = self.keycloak_fetch_token()
        if access_token is None:
            return None

        return FlaskLoginAuthLibUser(flask.session['id_token'])

    def keycloak_fetch_token(self):
        # type: (...) -> t_.Optional[str]
        if 'oa_token' not in flask.session:
            return None

        now = time.time()
        oa_token = flask.session['oa_token']
        # get current access token
        # check if access token is still valid
        # if current access token is valid, use token for request
        # if current access token is invalid, use refresh token to obtain new access token
        # if successfully, update current access token, current refresh token
        # if current access token is valid, use token for request

        if oa_token['expires_at'] - 2 < now:  # refresh 2 seconds before access token expires
            try:
                refreshed_token = self.oauth_service.keycloak.fetch_access_token(
                    refresh_token=oa_token['refresh_token'],
                    grant_type='refresh_token'
                )

            except OAuthError as e:
                if e.error != 'invalid_grant':
                    raise

                clear_session()
                return None

            id_token = self.oauth_service.keycloak.parse_id_token(refreshed_token)
            flask.session['id_token'] = id_token
            refreshed_token.pop('id_token', None)
            oa_token = flask.session['oa_token'] = refreshed_token

            # Mark flask.session tampered with.
            flask.session.modified = flask.session.accessed = True

        return oa_token['access_token']

    def keycloak_authorize_access_token(self):
        oa_token = self.oauth_service.keycloak.authorize_access_token()

        # OAuth Token contains User Info encoded in JWT.  Should we drop it?
        id_token = self.oauth_service.keycloak.parse_id_token(oa_token)
        if id_token:
            # https://openid.net/specs/openid-connect-core-1_0.html#IDToken
            flask.session['id_token'] = id_token
            # https://www.rfc-editor.org/rfc/rfc6749#section-4.1.4
            new_token = dict(oa_token)
            new_token.pop('id_token', None)
            flask.session['oa_token'] = new_token

        return oa_token

    def keycloak_authorize_redirect(
            self,
            redirect_uri
    ):
        # type: (...) -> flask.BaseResponse
        return self.oauth_service.keycloak.authorize_redirect(redirect_uri)

    def keycloak_logout(self):
        oa_token = flask.session.get('oa_token')
        if oa_token is not None:
            # propagate logout to Keycloak
            refresh_token = oa_token['refresh_token']
            end_session_endpoint = f'{issuer}/protocol/openid-connect/logout'

            requests.post(
                end_session_endpoint,
                data={
                    "client_id": clientId,
                    "client_secret": clientSecret,
                    "refresh_token": refresh_token,
                })
            # We ignore the response

        clear_session()


login_manager = FlaskAuthLibLoginManager(app)
