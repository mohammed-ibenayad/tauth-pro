from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header

from .abc_authenticator import Authenticator


class TTokenBaseAuthentication(BaseAuthentication):
    """
    Custom Django Rest Framework BaseAuthentication to identify coming API requests using the
    same third-party service supporting token-based authentication.

    Any implementation inheriting from this class needs to define the 'get_authenticator()' method
    which is responsible of passing the instantiated authenticator to this class.
    """

    keyword = 'Bearer'

    def __init__(self):
        kc = self.get_authenticator()
        kc.connect()
        self._authenticator = kc

    def authenticate_header(self, request):
        return self.keyword

    def authenticate(self, request):

        token = self.verify_request_token(request)
        try:
            user_info = self._authenticator.validate_credentials(request_token=token)
        except Exception as ex:
            pass

        is_authorized = user_info.get('is_authorized', False)
        access_token = user_info.get('access_token', None)
        username = user_info.get('preferred_username', None)

        if not is_authorized:
            msg = _('Invalid token.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            auth_user = get_user_model()
            user = auth_user.objects.get(username=username)
        except auth_user.DoesNotExist:
            msg = _('User inactive or deleted.')
            raise exceptions.AuthenticationFailed(msg)

        return user, access_token

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")

    def verify_request_token(self, request):

        token = None

        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        finally:
            return token
