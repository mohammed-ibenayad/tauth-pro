from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.views.decorators.debug import sensitive_variables

from rest_framework import exceptions

from keycloak import KeycloakOpenID, KeycloakAdmin
from keycloak.exceptions import KeycloakError

from ..core.abc_authenticator import Authenticator


class KeycloakAuthenticator(Authenticator):
    _authenticator = None
    _adm_authenticator = None

    def get_authenticator(self):
        return self._authenticator

    def get_adm_authenticator(self):
        return self._adm_authenticator

    @sensitive_variables('credentials', 'password')
    def validate_credentials(self, **credentials) -> dict:

        """
        Throws KeycloakError exception if credentials are invalid
        Or user is inactive in Keycloak Database
        """

        auth_data = {}
        try:
            username = credentials.get('username', None)
            password = credentials.get('password', None)
            request_token = credentials.get('request_token', None)
            refresh_token = credentials.get('refresh_token', None)

            if username and password:
                res = self.get_authenticator().token(username=username, password=password)
            elif request_token:
                res = self.get_authenticator().userinfo(token=request_token)
            elif refresh_token:
                res = self.get_authenticator().refresh_token(refresh_token=refresh_token)
            else:
                msg = _('Missing authentication credentials.')
                raise exceptions.AuthenticationFailed(msg)

            auth_data['access_token'] = res.get('access_token', None)
            auth_data['refresh_token'] = res.get('refresh_token', None)
            auth_data['global_id'] = res.get('sub', None)
            auth_data['username'] = res.get('preferred_username', None)
            auth_data['email'] = res.get('email', None)
            auth_data['expires_in'] = res.get('expires_in', None)
            auth_data['refresh_expires_in'] = res.get('refresh_expires_in', None)
            auth_data['is_authorized'] = True

            return auth_data

        except KeycloakError as kce:
            raise exceptions.AuthenticationFailed(kce.error_message)

    @sensitive_variables('password', 'client_id', 'client_secret_key', 'config')
    def connect(self):
        try:
            config = settings.KEYCLOAK_CONFIG
            server_url = config['KEYCLOAK_SERVER_URL']
            client_id = config['KEYCLOAK_CLIENT_ID']
            realm = config['KEYCLOAK_REALM']
            client_secret_key = config['KEYCLOAK_CLIENT_SECRET_KEY']

        except KeyError as e:
            raise Exception("Keycloak Connection Config Missing.")

        try:
            self._authenticator = KeycloakOpenID(server_url=server_url,
                                                 client_id=client_id,
                                                 realm_name=realm,
                                                 client_secret_key=client_secret_key)
        except KeycloakError as kce:
            raise exceptions.AuthenticationFailed(kce.error_message)

    @sensitive_variables('admin_pwd', 'config')
    def connect_adm(self):

        try:
            config = settings.KEYCLOAK_CONFIG
            server_url = config['KEYCLOAK_SERVER_URL']
            realm = config['KEYCLOAK_REALM']
            admin_usr = config['KEYCLOAK_REALM_ADMIN_USR']
            admin_pwd = config['KEYCLOAK_REALM_ADMIN_PWD']

        except KeyError as e:
            raise Exception("Keycloak ADM Connection Config Missing.")

        try:
            self._adm_authenticator = KeycloakAdmin(server_url=server_url,
                                                    username=admin_usr,
                                                    password=admin_pwd,
                                                    realm_name=realm)

        except KeycloakError as kce:
            raise exceptions.AuthenticationFailed(kce.error_message)

    def create_user(self, **kwargs):

        try:
            email = kwargs["email"]
            username = kwargs["username"]

        except KeyError:
            msg = _('User Credentials not provided or incorrect.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            if self.get_adm_authenticator() is None:
                self.connect_adm()

            payload = {"email": email,
                       "username": username,
                       "enabled": 'true',
                       "credentials": [
                           {
                               "type": "password",
                               "temporary": 'true',
                               "value": ""
                           }
                       ]
                       }

            return self.get_adm_authenticator().create_user(payload=payload, exist_ok=False)

        except KeycloakError as kce:
            raise exceptions.AuthenticationFailed(kce.error_message)

    def update_user(self, user_id, **kwargs):

        payload = {}

        for key in kwargs:
            if str(key).lower() == 'password':
                payload["credentials"] = [{"type": "password", "value": kwargs[key]}]
            else:
                payload[key] = kwargs[key]

        try:
            if self.get_adm_authenticator() is None:
                self.connect_adm()

            return self.get_adm_authenticator().update_user(user_id=user_id, payload=payload)

        except KeycloakError as kce:
            raise exceptions.AuthenticationFailed(kce.error_message)

    def delete_user(self, user_id):

        try:
            if self.get_adm_authenticator() is None:
                self.connect_adm()

            return self.get_adm_authenticator().delete_user(user_id=user_id)

        except KeycloakError as kce:
            raise exceptions.AuthenticationFailed(kce.error_message)

    def logout(self, user_id):
        try:

            self.get_authenticator().logout(refresh_token=user_id)

        except KeycloakError as kce:
            raise exceptions.NotFound(kce.error_message)
