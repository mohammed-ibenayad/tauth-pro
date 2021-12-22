from abc import abstractmethod

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.utils.crypto import get_random_string
from django.views.decorators.debug import sensitive_variables

from .abc_authenticator import Authenticator


class TBaseBackend(BaseBackend):
    """
    Custom Django BaseBackend to authenticate users on a authentication service using login
    credentials (username and password).

    Any implementation inheriting from this class needs to define the 'get_authenticator()' method
    which is responsible of passing the instantiated authenticator to this class.
    """

    keyword = 'Bearer'

    @abstractmethod
    def after_authentication(self, user: get_user_model(), access_token=None):
        pass

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")

    def get_user(self, user_id):

        try:
            user_model = get_user_model()
            user = user_model.objects.get(pk=user_id)
        except user_model.DoesNotExist:
            return None

        return user

    @sensitive_variables('password', 'access_token')
    def authenticate(self, request, **kwargs):
        """
        Overriding the parent method from BaseBackend. This method is responsible of returning
        the Django authenticated user. Any inheriting class has the possibility of defining
        custom behavior after authentication completed through the 'after_authentication()' method.
        """

        is_authorized = False
        access_token = None
        refresh_token = None

        username = kwargs.get('username', None)
        password = kwargs.get('password', None)

        token_data = self.get_authenticator().validate_credentials(username=username, password=password)

        # TODO Deactivate Django user if not defined on the authenticator

        if token_data is not None:
            is_authorized = token_data.get('is_authorized', False)
            access_token = token_data.get('access_token', None)
            refresh_token = token_data.get('refresh_token', None)

        if not is_authorized:
            return None

        user = self._get_user_by_username(username=username)
        if user is None:
            user = self._get_user_by_email(username=username)

        auth_user = self.get_user_info_by_token(access_token)

        if user is None:

            # Create user replica using the Django User model.
            user = self._create_user(**auth_user)
        else:
            # Update the user replica based on the authenticator data.
            self._update_user(user, **auth_user)

        user.extra_transients = {'access_token': access_token, 'refresh_token': refresh_token}

        # Execute some custom behavior after authentication
        # in the class inheriting from TBaseBackend.
        self.after_authentication(user, access_token)

        return user

    def get_user_info_by_token(self, access_token) -> dict:

        user = self.get_authenticator().validate_credentials(request_token=access_token)
        username = user.get('username', None)
        email = user.get('email', None)
        return {'username': username, 'email': email}

    def _get_user_by_username(self, username):

        user_model = get_user_model()
        try:
            user = user_model.objects.get(username=username)
        except user_model.DoesNotExist:
            return None
        else:
            return user

    def _get_user_by_email(self, username):

        user_model = get_user_model()
        try:
            user = user_model.objects.get(email=username)
        except user_model.DoesNotExist:
            return None
        else:
            return user

    def _create_user(self, **kwargs) -> get_user_model():
        auth_user = get_user_model()
        username = kwargs.get('username', None)
        email = kwargs.get('email', None)

        user = auth_user(username=username)
        user.is_staff = True
        user.is_superuser = False
        user.email = email
        user.password = get_random_string(length=50)
        user.save()

        return user

    def _update_user(self, user: get_user_model(), **kwargs):
        email = kwargs.get('email', None)
        if email is not None:
            user.email = email

        user.save()


