from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from crypto_app.models import Partipicant
from crypto_app.models import PythonCipher, JSCipher, ExecutableCipher
from django.views.decorators.csrf import csrf_exempt
import bcrypt

USER_ID = "user_id"
AUTHENTICATED = "authenticated"

def index(request):

    logged_in = request.session.get(AUTHENTICATED)
    if logged_in == None:
        logged_in = False
    else:
        logged_in = bool(logged_in)

    if not logged_in:
        return render(request, "crypto_app/index.html", {"logged_in": False})

    uuid = request.session[USER_ID]
    person = Partipicant.objects.get(uuid = uuid)

    return render(request, "crypto_app/index.html", {"logged_in": True, "nick": person.nick})

def register(request):
    logged_in = request.session.get(AUTHENTICATED)
    if logged_in == None:
        logged_in = False
    else:
        logged_in = bool(logged_in)

    if logged_in:
        return HttpResponseRedirect("/")

    if request.method == "POST":
        nick = request.POST["nick"]
        password1 = request.POST["password1"].encode('utf-8')
        password2 = request.POST["password2"].encode('utf-8')

        if(password1 != password2):
            return render(request, "crypto_app/register.html", {"error": 2})

        if Partipicant.objects.filter(nick=nick).count() > 0:
            return render(request, "crypto_app/register.html", {"error": 1})

        user = Partipicant.objects.create(nick=nick, password_hash=bcrypt.hashpw(password1, bcrypt.gensalt()).decode('utf-8'))

        user.save()
        request.session[USER_ID] = str(user.uuid)
        request.session[AUTHENTICATED] = True

        return HttpResponseRedirect("/")
    else:

        return render(request, "crypto_app/register.html", {"error": 0})

def logout(request):
    logged_in = request.session.get(AUTHENTICATED)
    if logged_in == True:
        request.session[AUTHENTICATED] = False
    return HttpResponseRedirect("/")

def login(request):
    logged_in = request.session.get(AUTHENTICATED)
    if logged_in == None:
        logged_in = False
    else:
        logged_in = bool(logged_in)

    if logged_in:
        return HttpResponseRedirect("/")

    if request.method == "POST":
        nick = request.POST["nick"]
        password = request.POST["password"].encode('utf-8')

        try:
            user = Partipicant.objects.get(nick=nick)

            if bcrypt.checkpw(password, user.password_hash.encode('utf-8')):
                request.session[USER_ID] = str(user.uuid)
                request.session[AUTHENTICATED] = True
            else:
                return render(request, "crypto_app/login.html", {"error": True})

        except:
            return render(request, "crypto_app/login.html", {"error": True})

        return HttpResponseRedirect("/")
    else:
        return render(request, "crypto_app/login.html", {"error": False})

def newcipher(request):
    logged_in = request.session.get(AUTHENTICATED)
    if logged_in == None:
        logged_in = False
    else:
        logged_in = bool(logged_in)

    if not logged_in:
        return HttpResponseRedirect("/")

    if request.method == "POST":

        uuid = request.session[USER_ID]
        person = Partipicant.objects.get(uuid=uuid)

        name = request.POST["name"]
        language = request.POST["language"]

        if language == "py":
            cipher = PythonCipher.objects.create(author=person, name=name, isReady=False, encryptFun="", decryptFun="")
            cipher.save()
            return HttpResponseRedirect("/edit_python_cipher/{}".format(cipher.id))
        elif language == "js":
            cipher = JSCipher.objects.create(author=person, name=name, isReady=False, encryptFun="", decryptFun="")
            cipher.save()
            return HttpResponseRedirect("/edit_js_cipher/{}".format(cipher.id))
        else:
            cipher = ExecutableCipher.objects.create(author=person, name=name, isReady=False, binary=b"")
            cipher.save()
            return HttpResponseRedirect("/edit_executable_cipher/{}".format(cipher.id))
    else:
        return render(request, "crypto_app/newcipher.html")

@csrf_exempt
def edit_python_cipher(request, cipher_id):
    logged_in = request.session.get(AUTHENTICATED)
    if logged_in == None:
        logged_in = False
    else:
        logged_in = bool(logged_in)

    if not logged_in:
        return HttpResponseRedirect("/")

    uuid = request.session[USER_ID]
    person = Partipicant.objects.get(uuid=uuid)

    try:
        cipher = PythonCipher.objects.get(id=cipher_id, author=person)
    except:
        return HttpResponseRedirect("/")

    if request.method == "POST":

        cipher.encryptFun = request.POST["enc"]
        cipher.decryptFun = request.POST["dec"]
        cipher.isReady = request.POST["vis"]=="true"
        print(cipher.isReady)
        cipher.save()

        return HttpResponse("OK")
    else:
        return render(request, "crypto_app/edit_python_cipher.html", {'cipher_name': cipher.name, "enc":cipher.encryptFun, "dec":cipher.decryptFun, "ready":cipher.isReady})

