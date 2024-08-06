from .models import TextEncryptionModel
from django import forms


algorithm = [
    ('--Select Algorithm--', '--select algorithm--'),
    ('RSA', 'RSA'),
    ('AES', 'AES'),
    ('BLOW FISH', 'BLOW FISH')
]


def getall_filenames():
    try:
        data = [(i.filename, i.filename)
                for i in TextEncryptionModel.objects.all()]
        print(data)
    except:
        data = []

    return data


class UserSignupForm(forms.Form):
    username = forms.CharField(required=True, label='',
                               widget=forms.TextInput(
                                   attrs={'class': 'form-control', 'placeholder': 'Enter User Name'})
                               )

    useremail = forms.EmailField(
        label='', required=True,
        widget=forms.EmailInput(
            attrs={'class': 'form-control', 'placeholder': 'Enter User Email'})
    )

    password = forms.CharField(
        label='', required=True,
        widget=forms.PasswordInput(
            attrs={'class': 'form-control', 'placeholder': 'Enter Password'})
    )
    confirmpassword = forms.CharField(
        label='', required=True,
        widget=forms.PasswordInput(
            attrs={'class': 'form-control', 'placeholder': 'Enter Confirm Password'})
    )


class UserSigninForm(forms.Form):
    useremail = forms.EmailField(
        label='', required=True,
        widget=forms.EmailInput(
            attrs={'class': 'form-control', 'placeholder': 'Enter User Email'})
    )

    password = forms.CharField(
        label='', required=True,
        widget=forms.PasswordInput(
            attrs={'class': 'form-control', 'placeholder': 'Enter Password'})
    )


class UploadForm(forms.Form):

    usertext = forms.CharField(label='', widget=forms.Textarea(
        attrs={'class': 'form-control', 'placeholder': 'Enter Text'}))
    filename = forms.CharField(label='', widget=forms.TextInput(
        attrs={'class': 'form-control', 'placeholder': 'Enter File Name', 'height': '25px'}))
    algorithm = forms.ChoiceField(label='', choices=algorithm, widget=forms.Select(
        attrs={'class': 'form-control'}))


class HideDataForm(forms.Form):
    algorithm = forms.ChoiceField(label='', choices=algorithm, widget=forms.Select(
        attrs={'class': 'form-control'}))


class DecryptForm(forms.Form):
    fileid = forms.CharField(label='', widget=forms.TextInput(
        attrs={'class': 'form-control', 'placeholder': 'Enter File Id'}))
    imagefile = forms.FileField(label='Upload Stegano Image', widget=forms.FileInput(
        attrs={'class': 'form-control'}))
    filename = forms.CharField(label='', widget=forms.TextInput(
        attrs={'class': 'form-control', 'placeholder': 'Enter File Name', 'height': '25px'}))
    algorithm = forms.ChoiceField(label='', choices=algorithm, widget=forms.Select(
        attrs={'class': 'form-control'}))
    key = forms.CharField(label='', widget=forms.TextInput(
        attrs={'class': 'form-control', 'placeholder': 'Enter Key'}))
