from unittest.mock import patch, Mock, create_autospec
from uuid import uuid1

from django.contrib.auth import get_user_model
from django.test import TestCase
from tauth.forms import TAuthPasswordSetForm
from tauth.core.abc_authenticator import Authenticator


class TestAuthPwdSetForm(TestCase):

    def setUp(self) -> None:
        self.sub = '31629373-67c4-11ec-b894-34cff69a7a94'
        mock_auth = patch('tauth.forms.TAuthPasswordSetForm.get_authenticator')
        self.mock_auth_p = mock_auth.start()
        self.mock_auth_p.return_value = create_autospec(Authenticator)

        mock_getsub = patch('tauth.forms.TAuthPasswordSetForm.get_sub')
        self.mock_getsub_p = mock_getsub.start()
        self.mock_getsub_p = Mock(return_value=self.sub)

        self.user = get_user_model().objects.create(username='auth_user', email='auth_user@email.com')

    def tearDown(self) -> None:
        self.mock_auth_p.stop()

    def test_auth_pwd_form_is_valid(self):
        pwd = {'new_password1': 'usersecret', 'new_password2': 'usersecret'}
        form = TAuthPasswordSetForm(self.user, data=pwd)
        self.assertTrue(form.is_valid())

    def test_auth_pwd_is_saved(self):
        payload = {'new_password1': 'usersecret', 'new_password2': 'usersecret'}
        form = TAuthPasswordSetForm(self.user, data=payload)
        form.is_valid()
        user = form.save()
        self.assertTrue(user.check_password('usersecret'))

    def test_auth_upd_pwd_mock_is_called(self):
        payload = {'new_password1': 'usersecret', 'new_password2': 'usersecret'}
        form = TAuthPasswordSetForm(self.user, data=payload)
        form.is_valid()
        form.save()
        self.mock_auth_p.return_value.update_user.assert_called_once()



