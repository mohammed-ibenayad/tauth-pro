from abc import abstractmethod

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from django.views.decorators.debug import sensitive_variables
from django.utils.crypto import get_random_string

from .abc_authenticator import Authenticator


class TBaseBackend(BaseBackend):
    """
    Custom Django BaseBackend to authenticate users on a authentication service using login
    credentials (username and password).

    Any implementation inheriting from this class needs to define the 'get_authenticator()' method
    which is responsible of passing the instantiated authenticator to this class.
    """

    keyword = 'Bearer'

    @sensitive_variables('password', 'access_token')
    def authenticate(self, request, **kwargs):
        """
        Overriding the parent method from BaseBackend. This method is responsible of returning
        the Django authenticated user.  Any inheriting class has the possibility of defining
        custom behavior after authentication completed through the 'after_authentication()' method.
        """

        is_authorized = False
        access_token = None

        username = kwargs.get('username', None)
        password = kwargs.get('password', None)

        token_data = self.get_authenticator().validate_credentials(username=username, password=password)

        # TODO Deactivate Django user if not defined on the authenticator

        if token_data:
            is_authorized = token_data.get('is_authorized', False)
            access_token = token_data.get('access_token', None)

        if not is_authorized:
            return None

        # Logging using username.
        auth_user = get_user_model()
        try:
            user = auth_user.objects.get(username=username)
        except auth_user.DoesNotExist:
            pass
        else:
            self.after_authentication(user, access_token)
            return user

        # Logging using email if with username failed.
        try:
            user = auth_user.objects.get(email=username)
        except auth_user.DoesNotExist:

            user_data = self.get_authenticator().validate_credentials(request_token=access_token)
            username = user_data.get('username', None)
            email = user_data.get('email', None)
            kwargs = {'username': username, 'email': email}

            # Create user replica using Django User model.
            user = self.create_user(**kwargs)

        self.after_authentication(user, access_token)
        return user

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")

    @abstractmethod
    def after_authentication(self, user: get_user_model(), access_token=None):
        pass

    def create_user(self, **kwargs) -> get_user_model():
        auth_user = get_user_model()
        username = kwargs.get('username', None)
        email = kwargs.get('email', None)

        user = auth_user(username=username)
        user.is_staff = False
        user.is_superuser = False
        user.email = email
        user.password = get_random_string()
        user.save()

        return user

    def get_user(self, user_id):

        try:
            auth_user = get_user_model()
            user = auth_user.objects.get(pk=user_id)
        except auth_user.DoesNotExist:
            return None

        return user
