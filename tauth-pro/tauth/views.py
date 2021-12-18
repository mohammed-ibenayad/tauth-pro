from abc import abstractmethod

from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth import logout as django_logout
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework import status, generics
from rest_framework.response import Response

from . import serializers
from .core.abc_authenticator import Authenticator


class UserAuthViewsMixin:

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")


class UserLoginView(UserAuthViewsMixin, generics.GenericAPIView):

    serializer_class = serializers.LoginViewSerializer

    USERNAME_FIELD = 'username'
    PASSWORD_FIELD = 'password'
    ACCESS_TOKEN_FIELD = 'access_token'
    REFRESH_TOKEN_FIELD = 'refresh_token'

    @abstractmethod
    def before_login(self, request, *args, **kwargs):
        pass

    @abstractmethod
    def after_login(self, request, *args, **kwargs):
        pass

    def _perform_login(self, request, *args, **kwargs):

        token = {}
        username = kwargs.get(self.USERNAME_FIELD, None)
        password = kwargs.get(self.PASSWORD_FIELD, None)

        user = authenticate(request, username=username, password=password)

        if user is None:
            msg = _('Invalid User Credentials.')
            raise exceptions.AuthenticationFailed(msg)

        if hasattr(user, 'extra_transients'):
            token['access_token'] = user.extra_transients.get(self.ACCESS_TOKEN_FIELD, None)
            token['refresh_token'] = user.extra_transients.get(self.REFRESH_TOKEN_FIELD, None)

        if token:
            django_login(request, user)

        return token

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data,
                                         context={'request': request})

        serializer.is_valid(raise_exception=True)

        self.before_login(request, *args, **kwargs)
        token = self._perform_login(request, **serializer.validated_data)
        self.after_login(request, *args, **kwargs)

        return Response(token, status=status.HTTP_200_OK)


class UserLogoutView(UserAuthViewsMixin, generics.GenericAPIView):

    serializer_class = serializers.LogoutViewSerializer

    LOGOUT_TOKEN_FIELD = 'logout_token'

    @abstractmethod
    def before_logout(self, request, *args, **kwargs):
        pass

    @abstractmethod
    def after_logout(self, request, *args, **kwargs):
        pass

    def _perform_logout(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data,
                                         context={'request': request})

        serializer.is_valid(raise_exception=True)

        logout_token = request.data.get(self.LOGOUT_TOKEN_FIELD, None)
        self.get_authenticator().logout(token=logout_token)

        django_logout(request)

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data,
                                         context={'request': request})

        serializer.is_valid(raise_exception=True)

        self.before_logout(request, *args, **kwargs)
        self._perform_logout(request, **serializer.validated_data)
        self.after_logout(request, *args, **kwargs)

        msg = _("Logout successful")

        return Response(data=msg, status=status.HTTP_200_OK)


class UserRefreshTokenView(UserAuthViewsMixin, generics.GenericAPIView):

    serializer_class = serializers.RefreshTokenViewSerializer

    REFRESH_TOKEN_FIELD = 'refresh_token'

    def _refresh_token(self, request, *args, **kwargs) -> dict:
        refresh_token = kwargs.get(self.REFRESH_TOKEN_FIELD, None)
        return self.get_authenticator().validate_credentials(refresh_token=refresh_token)

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data,
                                         context={'request': request})

        serializer.is_valid(raise_exception=True)

        token = self._refresh_token(request, **serializer.validated_data)

        return Response(data=token, status=status.HTTP_200_OK)
