#
"""
OAuth API End-points
"""
import requests

import flask
import flask_login

from flask_keycloak.framework import app, login_manager


@app.route('/api/user_info')
@flask_login.login_required
def api_userinfo():
    # type: (...) -> flask.Response
    """
    Use logged in user's access token to query user info
    """
    access_token = flask_login.current_user.access_token
    issuer = login_manager.oauth_service.keycloak.load_server_metadata()['issuer']

    user_info_endpoint = f'{issuer}/protocol/openid-connect/userinfo'
    user_info_response = requests.post(
        user_info_endpoint,
        headers={'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'}
    )

    return flask.Response(user_info_response.text, status=200, content_type='application/json')


@app.route('/api/user_info2')
@flask_login.login_required
def api_userinfo2():
    # type: (...) -> flask.Response
    """
    Use logged in user's access token to query user info
    """
    oauth2_token = flask_login.current_user.oauth_token
    user_info = login_manager.oauth_service.keycloak.userinfo(token=oauth2_token)

    return flask.jsonify(user_info)
