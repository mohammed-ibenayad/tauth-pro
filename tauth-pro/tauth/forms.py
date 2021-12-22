from django.contrib.auth import forms as auth_forms
from django.core.exceptions import ValidationError
from rest_framework import exceptions as rest_exceptions

from .core.abc_authenticator import Authenticator


class TAuthPasswordSetForm(auth_forms.SetPasswordForm):
    """
    Customizing the Set Password Form to set the user password on the Authenticator database.
    For ease of implementation, we used this approach instead of managing password updates through
    a custom User model manager and customizing the set_password() method.
    """

    def get_authenticator(self) -> Authenticator:
        raise NotImplementedError("Subclasses should implement this!")

    def get_sub(self):
        raise NotImplementedError("Subclasses should implement this!")

    def save(self, *args, commit=True, **kwargs):
        user = super().save(commit=True)
        password = self.cleaned_data["new_password1"]

        self._update_user_password_on_authenticator(self.get_sub(), password)

        return user

    def _update_user_password_on_authenticator(self, user_id, password):

        try:
            self.get_authenticator().update_user(user_id=user_id, password=password)
        except Exception as ex:
            print(ex)
            raise ex


class TAuthPasswordChangeForm(TAuthPasswordSetForm, auth_forms.PasswordChangeForm):
    """
    Using functionalities offered already by TAuthPasswordSetForm to change the user password on the
    Authenticator database and overriding some of the methods from the Django Password Change Form.
    """

    def clean_old_password(self):
        """
        Check the old password validity in the Authenticator database.
        """
        old_password = self.cleaned_data["old_password"]
        creds = {'username': self.user.username, 'password': old_password}
        try:
            _ = self.get_authenticator().validate_credentials(**creds)
        except rest_exceptions.APIException:
            raise ValidationError(
                self.error_messages['password_incorrect'],
                code='password_incorrect',
            )
        else:
            return old_password
