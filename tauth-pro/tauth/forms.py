from abc import abstractmethod

from django.contrib.auth import forms as auth_forms


class AuthPwdSetForm(auth_forms.SetPasswordForm):
    """
    Customizing the Set Password Form to update the user password on the custom Authenticator DataBase.
    For ease of implementation, we used this approach instead of managing password updates through
    a custom User model manager and customizing the set_password() method.
    """

    @abstractmethod
    def after_save(self, *args, **kwargs):
        pass

    def save(self, *args, commit=True, **kwargs):
        user = super().save(commit=True)
        password = self.cleaned_data["new_password1"]

        kwargs_up = kwargs.copy()
        kwargs_up['user'] = user
        kwargs_up['password'] = password

        self.after_save(*args, **kwargs_up)

        return user

