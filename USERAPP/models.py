from django.db import models
import os

# Create your models here.


class TextEncryptionModel(models.Model):
    useremail = models.EmailField(null=True)
    filename = models.CharField(null=True, max_length=100)
    cipher_text = models.TextField(null=True)
    algorithm = models.CharField(null=True, max_length=50)
    elapsedtime = models.CharField(null=True, max_length=150)
    key = models.CharField(null=True, max_length=100)
    status = models.CharField(null=True, max_length=100, default="pending")

    class Meta:
        db_table = "Encryption"


class HideDataModel(models.Model):
    image = models.FileField(upload_to=os.path.join("static", "hidedata"))
    imagename = models.CharField(null=True, max_length=50)
    ciphertext = models.TextField(null=True)
    algorithm = models.CharField(null=True, max_length=100)

    class Meta:
        db_table = "Hidedata"


class RequestModel(models.Model):
    fileid = models.CharField(null=True, max_length=100)
    useremail = models.EmailField(null=True)
    filename = models.CharField(null=True, max_length=100)
    cipher_text = models.TextField(null=True)
    algorithm = models.CharField(null=True, max_length=50)
    elapsedtime = models.CharField(null=True, max_length=150)
    key = models.CharField(null=True, max_length=100)
    status = models.CharField(null=True, max_length=100, default="pending")
    requestedemail = models.EmailField(null=True)

    class Meta:
        db_table = "Requests"
