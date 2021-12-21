from django.contrib.auth import get_user_model
from django.test import TestCase
from tauth.forms import AuthPwdSetForm


class TestAuthPwdSetForm(TestCase):

    def setUp(self) -> None:
        self.userfix = get_user_model().objects.create(username='userfix', email='userfix@noemail.com')

    def tearDown(self) -> None:
        pass

    def test_auth_pwd_form_is_valid(self):
        pwd = {'new_password1': 'Bf@r!s2015', 'new_password2': 'Bf@r!s2015'}
        form = AuthPwdSetForm(self.userfix, data=pwd)
        self.assertTrue(form.is_valid())
        user = form.save()
        form.after_save()
        self.assertEqual(user, self.userfix)


