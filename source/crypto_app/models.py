from django.db import models
import uuid

# Create your models here.

class Partipicant(models.Model):
    nick = models.CharField(max_length=128)
    password_hash = models.CharField(max_length=128)

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

class PythonCipher(models.Model):
    name = models.TextField()
    isReady = models.BooleanField(default=False)

    encryptFun = models.TextField(blank=True)
    decryptFun = models.TextField(blank=True)

    author = models.ForeignKey('Partipicant', on_delete=models.CASCADE,)

class JSCipher(models.Model):
    name = models.TextField()
    isReady = models.BooleanField(default=False)

    encryptFun = models.TextField(blank=True)
    decryptFun = models.TextField(blank=True)

    author = models.ForeignKey('Partipicant', on_delete=models.CASCADE, )

class ExecutableCipher(models.Model):
    name = models.TextField()
    isReady = models.BooleanField(default=False)

    binary = models.BinaryField(blank=True)

    author = models.ForeignKey('Partipicant', on_delete=models.CASCADE, )
