from abc import abstractmethod

from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth import logout as django_logout
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework import status, generics
from rest_framework.response import Response

from . import serializers
from .core.abc_authenticator import Authenticator


class UserLoginView(generics.GenericAPIView):

    serializer_class = serializers.LoginViewSerializer

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")

    @abstractmethod
    def before_login(self, request, *args, **kwargs):
        pass

    @abstractmethod
    def after_login(self, request, *args, **kwargs):
        pass

    def _perform_login(self, request, *args, **kwargs):

        token = {}
        username = kwargs.get('username', None)
        password = kwargs.get('password', None)

        user = authenticate(request, username=username, password=password)

        if user is None:
            msg = _('Invalid User Credentials.')
            raise exceptions.AuthenticationFailed(msg)

        if hasattr(user, 'extra_transients'):
            token['access_token'] = user.extra_transients.get('access_token', None)
            token['refresh_token'] = user.extra_transients.get('refresh_token', None)

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


class UserLogoutView(generics.GenericAPIView):

    serializer_class = serializers.LogoutViewSerializer

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")

    @abstractmethod
    def before_logout(self, request, *args, **kwargs):
        pass

    @abstractmethod
    def after_logout(self, request, *args, **kwargs):
        pass

    def _perform_logout(self, request, *args, **kwargs):
        logout_token = request.data.get('logout_token', None)
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


class UserRefreshTokenView(generics.GenericAPIView):

    serializer_class = serializers.RefreshTokenViewSerializer

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")

    def _refresh_token(self, request, *args, **kwargs) -> dict:
        refresh_token = kwargs.get('refresh_token', None)
        return self.get_authenticator().validate_credentials(refresh_token=refresh_token)

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data,
                                         context={'request': request})

        serializer.is_valid(raise_exception=True)

        token = self._refresh_token(request, **serializer.validated_data)

        return Response(data=token, status=status.HTTP_200_OK)
