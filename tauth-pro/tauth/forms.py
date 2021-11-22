from django.contrib.auth import forms


class AuthPwdSetForm(forms.SetPasswordForm):
    """
    Customizing the Set Password Form to update the user password on the custom Authenticator DataBase.
    For ease of implementation, we used this approach instead of managing password updates through
    a custom User model manager and customizing the set_password() method.
    """

    def update_app_user_pwd(self, user_id, password):
        raise NotImplementedError("Subclasses should implement this!")

    def save(self, *args, commit=True, **kwargs):
        user = super().save(commit=True)
        password = self.cleaned_data["new_password1"]

        self.update_app_user_pwd(user_id=user.id, password=password)

        return user

