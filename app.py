import json
import os

import certifi
import requests
from authlib.oauth2.rfc6749 import OAuth2Token
from flask import Flask, url_for, session
from flask import render_template, redirect
from authlib.integrations.flask_client import OAuth, token_update

print("Using cacerts from " + certifi.where())

app = Flask(__name__)
app.secret_key = '!secret'

issuer = os.getenv('ISSUER', 'https://id.acme.test:8443/auth/realms/acme-demo')
clientId = os.getenv('CLIENT_ID', 'flask-webapp')
clientSecret = os.getenv('CLIENT_SECRET', 'lkkoQDUdJUqYDHXZBVDodw2ocvqJEflP')
oidcDiscoveryUrl = f'{issuer}/.well-known/openid-configuration'


# def update_token(name, token, refresh_token=None, access_token=None):
#    if refresh_token:
#        item = OAuth2Token.find(name=name, refresh_token=refresh_token)
#    elif access_token:
#        item = OAuth2Token.find(name=name, access_token=access_token)
#    else:
#        return
#
#    # update old token
#    item.access_token = token['access_token']
#    item.refresh_token = token.get('refresh_token')
#    item.expires_at = token['expires_at']
#    item.save()


oauth = OAuth(app=app
              #              , update_token=update_token
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


@app.route('/')
def index():
    user = session.get('user')
    prettyIdToken = None
    if user is not None:
        prettyIdToken = json.dumps(user, sort_keys=True, indent=4)
    return render_template('index.html', idToken=prettyIdToken)


@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@app.route('/auth')
def auth():
    tokenResponse = oauth.keycloak.authorize_access_token()

    #userinfo = oauth.keycloak.userinfo(request)
    idToken = oauth.keycloak.parse_id_token(tokenResponse)

    if idToken:
        session['user'] = idToken
        session['tokenResponse'] = tokenResponse

    return redirect('/')


@app.route('/api')
def api():
    if not 'tokenResponse' in session:
        return "Unauthorized", 401
    
    # the following should be much easier...
    # see https://docs.authlib.org/en/latest/client/frameworks.html#auto-update-token
    tokenResponse = session['tokenResponse']
    # get current access token
    # check if access token is still valid
    # if current access token is valid, use token for request
    # if current access token is invalid, use refresh token to obtain new access token
    # if sucessfull, update current access token, current refresh token
    # if current access token is valid, use token for request

    # call userinfo endpoint as an example
    access_token = tokenResponse['access_token']
    userInfoEndpoint = f'{issuer}/protocol/openid-connect/userinfo'
    userInfoResponse = requests.post(userInfoEndpoint,
                                     headers={'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'})

    return userInfoResponse.text, 200


@app.route('/logout')
def logout():
    tokenResponse = session.get('tokenResponse')

    if tokenResponse is not None:
        # propagate logout to Keycloak
        refreshToken = tokenResponse['refresh_token']
        endSessionEndpoint = f'{issuer}/protocol/openid-connect/logout'

        requests.post(endSessionEndpoint, data={
            "client_id": clientId,
            "client_secret": clientSecret,
            "refresh_token": refreshToken,
        })

    session.pop('user', None)
    session.pop('tokenResponse', None)
    return redirect('/')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8700)
