from abc import abstractmethod
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout

from .core.abc_authenticator import Authenticator

from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework import exceptions


class UserLoginView(generics.GenericAPIView):

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")

    @abstractmethod
    def before_login(self, request):
        pass

    @abstractmethod
    def after_login(self, request):
        pass

    def login(self, request) -> dict:
        access_token = None
        refresh_token = None
        username = request.data.get('username', None)
        password = request.data.get('password', None)

        user = authenticate(request, username=username, password=password)
        if user:
            token_data = self.get_authenticator().validate_credentials(username=username, password=password)
            access_token = token_data.get('access_token', None)
            refresh_token = token_data.get('refresh_token', None)

        if user is None or access_token is None:
            msg = _('Invalid User Credentials.')
            raise exceptions.AuthenticationFailed(msg)

        login(request, user)

        return {'access_token': access_token, 'refresh_token': refresh_token}

    # @sensitive_post_parameters('password'))
    def post(self, request, *args, **kwargs):
        self.before_login(request)
        tokens = self.login(request)
        self.after_login(request)
        access_token = tokens.get('access_token', None)
        refresh_token = tokens.get('refresh_token', None)
        return Response({'access_token': access_token, 'refresh_token': refresh_token}, status=status.HTTP_200_OK)


class UserLogoutView(generics.GenericAPIView):

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")

    @abstractmethod
    def before_logout(self, request):
        pass

    @abstractmethod
    def after_logout(self, request):
        pass

    def logout(self, request):

        refresh_token = request.data.get('refresh_token', None)
        self.get_authenticator().logout(user_id=refresh_token)
        logout(request)

    def post(self, request, *args, **kwargs):
        self.before_logout(request)
        self.logout(request)
        self.after_logout(request)
        return Response(status=status.HTTP_200_OK)


class UserRefreshTokenView(generics.GenericAPIView):

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")

    def refresh_token(self, request) -> dict:
        refresh_token = request.data.get('refresh_token', None)
        token_data = self.get_authenticator().validate_credentials(refresh_token=refresh_token)
        access_token = token_data.get('access_token', None)
        new_refresh_token = token_data.get('refresh_token', None)
        return {'access_token': access_token, 'new_refresh_token': new_refresh_token}

    def post(self, request, *args, **kwargs):
        tokens = self.refresh_token(request)
        access_token = tokens.get('access_token', None)
        new_refresh_token = tokens.get('new_refresh_token', None)
        return Response({'access_token': access_token, 'refresh_token': new_refresh_token}, status=status.HTTP_200_OK)