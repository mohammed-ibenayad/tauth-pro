from unittest.mock import patch, Mock, create_autospec

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from tauth.core.abc_authenticator import Authenticator


class TestBaseBackend(APITestCase):

    def test_get_authenticator_implementation(self):

        """
        Testing the case of a missing implementation of get_authenticator() method
        in the Base Backend class. In such a case, the exception NotImplementedError
        should be raised. Here, we are simulating the call via the login API.
        """

        payload = {'username': 'mayad', 'password': 'mysecret'}
        url = reverse('user-login')
        raised = False
        try:
            self.client.post(path=url, data=payload)
        except NotImplementedError as e:
            raised = True

        self.assertTrue(raised)


class TestLoginApi(APITestCase):

    def setUp(self) -> None:
        self.access_token = 'eyJsInR5cCIgOiAiSlUIIiA6ICJhSkxmVExVTzl.eyJqdGkiOiJhCCJMTEyMTUsIm5iZiI6.TETCzMBTO7qLUKcUK'
        self.refresh_token = 'eyJsInR5cCIgOiAiSlUIIiA6ICJhSkxmVExVTzl.eyJqdGkiOiJhCCJMTEyMTUsIm5iZiI6.TETCzMBTO7qLUKcUK'

        self.mock_auth = patch('tauth.core.base_backend.TBaseBackend.get_authenticator')
        self.mock_auth_p = self.mock_auth.start()
        self.mock_auth_p.return_value = create_autospec(Authenticator)

    def tearDown(self) -> None:
        self.mock_auth.stop()

    def test_login_api_with_username(self):
        """
        Testing the case of a valid response from the authenticator
        while trying to log in with a valid username and password.
        """
        self.mock_auth_p.return_value.validate_credentials = Mock(return_value={'access_token': self.access_token,
                                                                                'refresh_token': self.refresh_token,
                                                                                'is_authorized': True,
                                                                                'username': 'mayad',
                                                                                'email': 'mayad@example.com'})
        payload = {'username': 'mayad', 'password': 'mysecret'}
        url = reverse('user-login')
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('access_token', None), self.access_token)
        self.assertEqual(response.data.get('refresh_token', None), self.refresh_token)

    def test_login_api_with_email(self):
        """
        Testing the case of a valid response from the authenticator
        while trying to log in with a valid email and password.
        """
        self.mock_auth_p.return_value.validate_credentials = Mock(return_value={'access_token': self.access_token,
                                                                                'refresh_token': self.refresh_token,
                                                                                'is_authorized': True,
                                                                                'username': 'mayad',
                                                                                'email': 'mayad@example.com'})
        payload = {'username': 'mayad@example.com', 'password': 'mysecret'}
        url = reverse('user-login')
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('access_token', None), self.access_token)
        self.assertEqual(response.data.get('refresh_token', None), self.refresh_token)

    def test_login_api_with_existing_user_replica(self):
        """
        Testing the case of a valid response from the authenticator
        and the user Django replica already exists. In such a case,
        the user replica attributes need to be updated.
        """
        self.mock_auth_p.return_value.validate_credentials = Mock(return_value={'access_token': self.access_token,
                                                                                'refresh_token': self.refresh_token,
                                                                                'is_authorized': True,
                                                                                'username': 'mayad',
                                                                                'email': 'mayad@example.com'})
        existing_user = {'username': 'mayad', 'password': 'mysecret', 'email': 'bademail@example.com'}
        get_user_model().objects.create(**existing_user)
        url = reverse('user-login')

        # Connecting with username.
        payload = {'username': 'mayad', 'password': 'mysecret'}
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        try:
            user = get_user_model().objects.get(username='mayad')
            self.assertEqual(user.email, 'mayad@example.com')
        except get_user_model().DoesNotExist:
            pass

    def test_login_api_with_non_existing_user_replica(self):
        """
        Testing the case of a valid response from the authenticator and
        the user Django replica doesn't exist. In such a case, the user
        must be replicated in Django admin based on the authenticator data received.
        """
        self.mock_auth_p.return_value.validate_credentials = Mock(return_value={'access_token': self.access_token,
                                                                                'refresh_token': self.refresh_token,
                                                                                'is_authorized': True,
                                                                                'username': 'mayad',
                                                                                'email': 'mayad@example.com'})
        url = reverse('user-login')

        # Connecting with username.
        payload = {'username': 'mayad', 'password': 'mysecret'}
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        try:
            raised = False
            user = get_user_model().objects.get(username='mayad')
            self.assertEqual(user.username, 'mayad')
            self.assertEqual(user.email, 'mayad@example.com')
        except get_user_model().DoesNotExist:
            raised = True

        self.assertFalse(raised)

    def test_login_api_with_missing_token(self):
        """
        Testing the case of a missing token from the authenticator when
        validate_credentials() is returning an empty token dict.
        """
        self.mock_auth_p.return_value.validate_credentials = Mock(return_value={})
        payload = {'username': 'mayad', 'password': 'mysecret'}
        url = reverse('user-login')
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_login_api_with_unauthorized_user(self):
        """
        Testing the case of an unauthorized user from the authenticator when
        validate_credentials() is returning is_authorized = False.
        """
        self.mock_auth_p.return_value.validate_credentials = Mock(return_value={'access_token': self.access_token,
                                                                                'refresh_token': self.refresh_token,
                                                                                'is_authorized': False,
                                                                                'username': 'mayad',
                                                                                'email': 'mayad@example.com'})

        payload = {'username': 'mayad', 'password': 'mysecret'}
        url = reverse('user-login')
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class TestLogoutApi(APITestCase):

    def setUp(self) -> None:
        self.refresh_token = 'eyJsInR5cCIgOiAiSlUIIiA6ICJhSkxmVExVTzl.eyJqdGkiOiJhCCJMTEyMTUsIm5iZiI6.TETCzMBTO7qLUKcUK'
        self.mock_auth = patch('tauth.views.UserLogoutView.get_authenticator')
        self.mock_auth_p = self.mock_auth.start()
        self.mock_auth_p.return_value = create_autospec(Authenticator)

    def tearDown(self) -> None:
        self.mock_auth.stop()

    def test_logout_api_with_valid_token(self):
        """
        Testing the case of a valid JWT logout token.
        """
        self.mock_auth_p.return_value.logout = Mock()
        payload = {'logout_token': self.refresh_token}
        url = reverse('user-logout')
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_api_with_django_logout(self):
        """
        Testing the case of an effective logout where Django returning
        AnonymousUser after performing logout.
        """
        self.mock_auth_p.return_value.logout = Mock()
        payload = {'logout_token': self.refresh_token}
        url = reverse('user-logout')
        response = self.client.post(path=url, data=payload)
        self.assertIsInstance(response.wsgi_request.user, AnonymousUser)

    def test_logout_api_with_invalid_token(self):
        """
        Testing the case of an invalid JWT logout token (bad request).
        """
        self.mock_auth_p.return_value.logout = Mock()
        payload = {'logout_token': 'this is an invalid JWT token'}
        url = reverse('user-logout')
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_api_with_missing_token(self):
        """
        Testing the case of a missing logout token (bad request).
        """
        self.mock_auth_p.return_value.logout = Mock()
        payload = {}
        url = reverse('user-logout')
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TestRefreshTokenApi(APITestCase):

    def setUp(self) -> None:
        self.access_token = 'eyJsInR5cCIgOiAiSlUIIiA6ICJhSkxmVExVTzl.eyJqdGkiOiJhCCJMTEyMTUsIm5iZiI6.TETCzMBTO7qLUKcUK'
        self.refresh_token = 'eyJsInR5cCIgOiAiSlUIIiA6ICJhSkxmVExVTzl.eyJqdGkiOiJhCCJMTEyMTUsIm5iZiI6.TETCzMBTO7qLUKcUK'

        self.mock_auth = patch('tauth.views.UserRefreshTokenView.get_authenticator')
        self.mock_auth_p = self.mock_auth.start()
        self.mock_auth_p.return_value = create_autospec(Authenticator)

    def tearDown(self) -> None:
        self.mock_auth.stop()

    def test_refresh_token_api_with_valid_token(self):
        """
        Testing the case of a a valid response from the authenticator
        while providing a valid JWT refresh token.
        """
        self.mock_auth_p.return_value.validate_credentials = Mock(return_value={'access_token': self.access_token,
                                                                                'refresh_token': self.refresh_token})
        payload = {'refresh_token': self.refresh_token}
        url = reverse('user-refresh-token')
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get('access_token', None))
        self.assertIsNotNone(response.data.get('refresh_token', None))

    def test_refresh_token_api_with_invalid_token(self):
        """
        Testing the case of an invalid JWT refresh token (bad request).
        """
        self.mock_auth_p.return_value.validate_credentials = Mock()
        payload = {'refresh_token': 'this is an invalid JWT token'}
        url = reverse('user-refresh-token')
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_refresh_token_api_with_missing_token(self):
        """
        Testing the case of a missing refresh token (bad request).
        """
        self.mock_auth_p.return_value.validate_credentials = Mock()
        payload = {}
        url = reverse('user-refresh-token')
        response = self.client.post(path=url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
