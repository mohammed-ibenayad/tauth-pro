=================================
Third-party Django Authentication
=================================

This reusable app provides the following main features:

- An abstract Django BaseBackend class for authenticating users on a third-party auth service using login
credentials (username and password).

- An abstract Django Rest Framework BaseAuthentication class for authenticating token-based API requests
on the third-party auth service.

- This app implements a complete example using Keycloak (an open source identity and access management solution).

Quick start
-----------

1. Define a new authenticator implementation class (ex: keycloak_authenticator.py) with the following methods::

    def connect(self) -> object:

    def validate_credentials(self, **credentials) -> dict:

    def create_user(self, **kwargs):

    def update_user(self, user_id, **kwargs):

    def delete_user(self, user_id):

    def logout(self, user_id):

2. Instantiate your third-party authenticator - for example in your apps settings - like this ::

    authenticator: Authenticator

    def __init__(self, app_name, app_module):
        super().__init__(app_name, app_module)
        kc = KeycloakAuthenticator()
        kc.connect()
        self.authenticator = kc

3. Define your custom app backend and passing it to your Django project settings as follows::

    -- file: myDjangoApp/backends.py
    class CustomAuthBackend(TBaseBackend):

        def get_authenticator(self) -> Authenticator:

        config = apps.get_app_config('myDjangoApp')
        return config.authenticator

    -- file: settings.py
    AUTHENTICATION_BACKENDS = ('myDjangoApp.backends.CustomAuthBackend',)


4. To authenticate an existing user on the third-party service, and log it in your myDjangoApp,
call the following statements::

    def login(self, request):
        user = authenticate(request, username=username, password=password)

        if user is None:
            msg = _('Invalid User Credentials.')
            raise exceptions.AuthenticationFailed(msg)

        login(request, user)

5. To authenticate API requests (signed with a Token Bearer) on the third-party auth service, define your custom
authentication scheme for your DFR views as follows::

    class ViewsTokenAuth(TTokenBaseAuthentication):

        def get_authenticator(self):
            config = apps.get_app_config('DAA')
            return config.authenticator

    class myDjangoAppView(generics.GenericAPIView):
        authentication_classes = [ViewsTokenAuth]

