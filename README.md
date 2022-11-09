
Adapted from https://gist.github.com/thomasdarimont/6a3905778520b746ff009cf3a41643e9


To setup:

```shell
virtualenv flask_keycloak
source flask_keycloak/bin/activate

pip install -e .
```

To run:
```shell
FLASK_DEBUG=1 FLASK_APP=flask_keycloak.__main__:app flask run
```

Tested using keycloak 19.0.1
https://www.keycloak.org/docs/latest/authorization_services/index.html#_getting_started_hello_world_enabling_authz_services
