from dataclasses import fields
from django.forms import forms
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, PasswordResetForm
from .models import Profile

#Signupform
class SignUpX(UserCreationForm):
    def __init__(self, *args, **kwargs):
      super().__init__(*args, **kwargs)
      self.fields["username"].widget.attrs.update({
        'name':'username', 
        'class':'login-input', 
        'type':'text',
        'placeholder':'Username.', 
        'required':'required',
      })
      self.fields["email"].widget.attrs.update({
        'email':'email', 
        'class':'login-input', 
        'type':'text',
        'placeholder':'Email.', 
        'required':'required',
      })
      self.fields["password1"].widget.attrs.update({
        'password1':'password1', 
        'class':'login-input', 
        'type':'text',
        'placeholder':'Password..', 
        'required':'required',
      })
      self.fields["password2"].widget.attrs.update({
        'password2':'password2', 
        'class':'login-input', 
        'type':'text',
        'placeholder':'Confirm..', 
        'required':'required',
      })
    class Meta:
        model = User
        fields = ['username','email','password1','password2']
#recovermail
class RecoverX(PasswordResetForm):
    def __init__(self, *args, **kwargs):
      super().__init__(*args, **kwargs)
      self.fields["email"].widget.attrs.update({
        'email':'email', 
        'class':'login-input', 
        'type':'text',
        'placeholder':'Email.', 
        'required':'required',
      })

#updateuser
class UpdateUserForm(forms.ModelForm):
    username = forms.CharField(max_length=100,
                               required=True,
                               widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(required=True,
                             widget=forms.TextInput(attrs={'class': 'form-control'}))
    def __init__(self, *args, **kwargs):
      super().__init__(*args, **kwargs)
      self.fields["username"].widget.attrs.update({
        'name':'username', 
        'class':'login-input', 
        'type':'text',
        'placeholder':'Username.', 
        'required':'required',
      })
      self.fields["email"].widget.attrs.update({
        'email':'email', 
        'class':'login-input', 
        'type':'text',
        'placeholder':'Email.', 
        'required':'required',
      })

    class Meta:
        model = User
        fields = ['username', 'email']

#updateprofile
class UpdateProfileForm(forms.ModelForm):
    profilepic = forms.ImageField(widget=forms.FileInput(attrs={'class': 'form-control-file'}))

    class Meta:
        model = Profile
        fields = ['profilepic']