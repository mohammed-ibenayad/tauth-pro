from rest_framework import serializers


class LoginViewSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)


class LogoutViewSerializer(serializers.Serializer):
    logout_token = serializers.RegexField('^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)', required=True)


class RefreshTokenViewSerializer(serializers.Serializer):
    refresh_token = serializers.RegexField('^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)', required=True)
