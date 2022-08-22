#
import typing as t_

import time
import json

import flask
import flask_login

from flask_keycloak.framework import app, FlaskLoginAuthLibUser

# Flask Route Imports
import flask_keycloak.views.iam  # pylint: disable=unused-import
import flask_keycloak.views.api  # pylint: disable=unused-import


@app.route('/')
def index():
    user = flask_login.current_user._get_current_object(
    )  # type: t_.Union[FlaskLoginAuthLibUser, flask_login.AnonymousUserMixin]

    pretty_id_token = None
    pretty_oa_token = None
    if user.is_authenticated:
        pretty_id_token = json.dumps(user.user_info, sort_keys=True, indent=4)
        pretty_oa_token = json.dumps(flask.session['oa_token'], sort_keys=True, indent=4)

    return flask.render_template(
        'index.html',
        id_token=pretty_id_token,
        oa_token=pretty_oa_token,
        now=int(time.time()),
    )


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8700)
