from django import forms

class RegisterForm(forms.Form):
    newEmail = forms.EmailField(label='Email')
    newName = forms.CharField(label='Имя пользователя', max_length=100)
    newPassword = forms.CharField(label='Пароль', widget=forms.PasswordInput)


class LoginForm(forms.Form):
    email = forms.EmailField(label='Email')
    password = forms.CharField(label='Пароль', widget=forms.PasswordInput)

class UpdateUserForm(forms.Form):
    newEmail = forms.EmailField(required=False, label='Электронная почта', max_length=100)
    newName = forms.CharField(required=False, label='Имя', max_length=100)
    newPassword = forms.CharField(required=False, label='Пароль', widget=forms.PasswordInput)