#
"""
Identity Access Management End-points
"""
import flask

from flask_keycloak.framework import app, login_manager


@app.route('/login')
def login():
    redirect_uri = flask.url_for('auth', _external=True)
    return login_manager.keycloak_authorize_redirect(redirect_uri)


@app.route('/auth')
def auth():
    login_manager.keycloak_authorize_access_token()

    return flask.redirect('/')


@app.route('/logout')
def logout():
    login_manager.keycloak_logout()
    return flask.redirect('/')
