import base64
import os

from django.conf import settings
from django.http import HttpResponse

from tester.crypto import decrypt, encrypt


def index(request):
    return HttpResponse("Hello World!")


def hamlet(request, key):
    text = open(settings.BASE_DIR + "/crypto_app/static/hamlet.txt").read()
    encoded = base64.b64encode(text)
    return HttpResponse(encrypt(encoded, key))


# Known Plaintext Attack
def kpa(request, text):
    key = os.urandom(16)
    return HttpResponse(encrypt(text, key))


# Encrypt with gievn plaintext key pair
def encrypter(request, text, key):
    encrypted = encrypt(text, key)
    return HttpResponse(encrypted)


# Decrypt with given ciphertext key pair
def decrypter(request, ciphertext, key):
    decrypted = decrypt(ciphertext, key)
    return HttpResponse(decrypted)
