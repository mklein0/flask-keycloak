import time
import json
import os

import certifi
import flask
import requests

from flask import Flask, url_for, session
from flask import render_template, redirect

from authlib.integrations.flask_client import OAuth, OAuthError

# from authlib.oauth2.rfc6749 import OAuth2Token
# from authlib.integrations.flask_client import token_update

print("Using cacerts from " + certifi.where())

app = Flask(__name__)
app.secret_key = '!secret'

issuer = os.getenv('ISSUER', 'https://id.acme.test:8443/auth/realms/acme-demo')
clientId = os.getenv('CLIENT_ID', 'flask-webapp')
clientSecret = os.getenv('CLIENT_SECRET', 'lkkoQDUdJUqYDHXZBVDodw2ocvqJEflP')
oidcDiscoveryUrl = f'{issuer}/.well-known/openid-configuration'

# We do not handle OAuth2 tokens separate from authentication server, so no need to hold them
# beyond the session.

# def update_token(
#         name,
#         token,
#         refresh_token=None,
#         access_token=None
# ):
#     import pdb; pdb.set_trace()
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


oauth = OAuth(
    app=app,
    # update_token=update_token,
)
oauth.register(
    name='keycloak',
    client_id=clientId,
    client_secret=clientSecret,
    server_metadata_url=oidcDiscoveryUrl,
    client_kwargs={
        'scope': 'openid email profile',
        'code_challenge_method': 'S256'  # enable PKCE
    },
)


def fetch_token():
    if 'authToken' not in session:
        return None

    now = time.time()
    authToken = session['authToken']
    # get current access token
    # check if access token is still valid
    # if current access token is valid, use token for request
    # if current access token is invalid, use refresh token to obtain new access token
    # if successfully, update current access token, current refresh token
    # if current access token is valid, use token for request

    if authToken['expires_at'] - 2 < now:  # refresh 2 seconds before access token expires
        try:
            new_response = oauth.keycloak.fetch_access_token(
                refresh_token=authToken['refresh_token'],
                grant_type='refresh_token'
            )

        except OAuthError as e:
            if e.error != 'invalid_grant':
                raise

            clear_session()
            return None

        session['authToken'].update(new_response)
        # Mark session tampered with.
        session.modified = session.accessed = True

    access_token = authToken['access_token']
    return access_token


@app.route('/')
def index():
    user = session.get('user')
    prettyIdToken = None
    prettyAuthToken = None
    if user is not None:
        prettyIdToken = json.dumps(user, sort_keys=True, indent=4)
        prettyAuthToken = json.dumps(session['authToken'], sort_keys=True, indent=4)
    return render_template(
        'index.html',
        idToken=prettyIdToken,
        authToken=prettyAuthToken,
        now=int(time.time()),
    )


@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@app.route('/auth')
def auth():
    authToken = oauth.keycloak.authorize_access_token()

    # userinfo = oauth.keycloak.userinfo(request)
    idToken = oauth.keycloak.parse_id_token(authToken)
    if idToken:
        session['user'] = idToken
        session['authToken'] = authToken

    return redirect('/')


@app.route('/api')
def api():
    """
    Use logged in user's access token to query user info
    """
    access_token = fetch_token()
    if access_token is None:
        # User is not authenticated
        raise flask.abort(401)

    userInfoEndpoint = f'{issuer}/protocol/openid-connect/userinfo'
    userInfoResponse = requests.post(
        userInfoEndpoint,
        headers={'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'}
    )

    return userInfoResponse.text, 200


def clear_session():
    # type: (...) -> None
    session.pop('user', None)
    session.pop('authToken', None)


@app.route('/logout')
def logout():
    authToken = session.get('authToken')

    if authToken is not None:
        # propagate logout to Keycloak
        refreshToken = authToken['refresh_token']
        endSessionEndpoint = f'{issuer}/protocol/openid-connect/logout'

        requests.post(
            endSessionEndpoint,
            data={
                "client_id": clientId,
                "client_secret": clientSecret,
                "refresh_token": refreshToken,
            })

    clear_session()
    return redirect('/')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8700)
