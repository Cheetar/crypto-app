from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from crypto_app.models import Partipicant
from crypto_app.models import PythonCipher, JSCipher, CPPCipher
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
import bcrypt
import traceback
import sys
import os
import json
import prctl
import subprocess
import signal
import random
import string
from py_mini_racer import py_mini_racer

USER_ID = "user_id"
AUTHENTICATED = "authenticated"

@never_cache
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

    py_ciph = list(map(lambda o: [o.name, "/edit_python_cipher/{}".format(o.id), "/execute_python_cipher/{}".format(o.id)], PythonCipher.objects.filter(author=person)))
    js_ciph = list(map(lambda o: [o.name, "/edit_js_cipher/{}".format(o.id), "/execute_js_cipher/{}".format(o.id)], JSCipher.objects.filter(author=person)))
    cpp_ciph = list(map(lambda o: [o.name, "/edit_cpp_cipher/{}".format(o.id), "/execute_cpp_cipher/{}".format(o.id)], CPPCipher.objects.filter(author=person)))

    user_ciphs = py_ciph+js_ciph+cpp_ciph

    py_ciph = list(
        map(lambda o: [o.name, o.author.nick, "/execute_python_cipher/{}".format(o.id)],
            PythonCipher.objects.filter(isReady=True)))
    js_ciph = list(map(lambda o: [o.name, o.author.nick, "/execute_js_cipher/{}".format(o.id)],
                       JSCipher.objects.filter(isReady=True)))
    cpp_ciph = list(
        map(lambda o: [o.name, o.author.nick, "/execute_cpp_cipher/{}".format(o.id)],
            CPPCipher.objects.filter(isReady=True)))

    public_ciphs = py_ciph + js_ciph + cpp_ciph

    return render(request, "crypto_app/index.html", {"logged_in": True, "nick": person.nick, "user_ciphers": user_ciphs, "public_ciphers": public_ciphs})

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

        try:
            name = request.POST["name"]
            language = request.POST["language"]
        except:
            return HttpResponseRedirect("/newcipher")

        if language == "py":
            cipher = PythonCipher.objects.create(author=person, name=name, isReady=False, encryptFun="def enc(text, key):", decryptFun="def dec(cipher, key):")
            cipher.save()
            return HttpResponseRedirect("/edit_python_cipher/{}".format(cipher.id))
        elif language == "js":
            cipher = JSCipher.objects.create(author=person, name=name, isReady=False, encryptFun="var enc = (text, key) =>\n{\n}\n", decryptFun="var dec = (cipher, key) =>\n{\n}\n")
            cipher.save()
            return HttpResponseRedirect("/edit_js_cipher/{}".format(cipher.id))
        elif language == "cpp":
            cipher = CPPCipher.objects.create(author=person, name=name, isReady=False, programCode="#include <string>\n\nusing namespace std;\n\nint main(int argc, char** argv)\n{\n    string op = string(argv[1]);\n    string arg = string(argv[2]);\n    string key = string(argv[3]);\n    return 0;\n}\n")
            cipher.save()
            return HttpResponseRedirect("/edit_cpp_cipher/{}".format(cipher.id))
        else:
            assert(0)
    else:
        return render(request, "crypto_app/newcipher.html")

@never_cache
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

        tmp = request.POST["enc"].lstrip().split("\n")
        tmp[0] = "def enc(text, key):"
        cipher.encryptFun = '\n'.join(tmp)

        tmp = request.POST["dec"].lstrip().split("\n")
        tmp[0] = "def dec(cipher, key):"
        cipher.decryptFun = '\n'.join(tmp)

        cipher.isReady = request.POST["vis"]=="true"
        cipher.save(force_update=True)

        return HttpResponse("OK")
    else:
        return render(request, "crypto_app/edit_python_cipher.html", {'cipher_name': cipher.name, "enc":cipher.encryptFun, "dec":cipher.decryptFun, "ready":cipher.isReady, "id":cipher.id})

@never_cache
@csrf_exempt
def edit_js_cipher(request, cipher_id):
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
        cipher = JSCipher.objects.get(id=cipher_id, author=person)
    except:
        return HttpResponseRedirect("/")

    if request.method == "POST":

        tmp = request.POST["enc"].lstrip().split("\n")
        tmp[0] = "var enc = (text, key) =>"
        cipher.encryptFun = '\n'.join(tmp)

        tmp = request.POST["dec"].lstrip().split("\n")
        tmp[0] = "var dec = (cipher, key) =>"
        cipher.decryptFun = '\n'.join(tmp)

        cipher.isReady = request.POST["vis"]=="true"
        cipher.save(force_update=True)

        return HttpResponse("OK")
    else:
        return render(request, "crypto_app/edit_js_cipher.html", {'cipher_name': cipher.name, "enc":cipher.encryptFun, "dec":cipher.decryptFun, "ready":cipher.isReady, "id":cipher.id})

@never_cache
@csrf_exempt
def edit_cpp_cipher(request, cipher_id):
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
        cipher = CPPCipher.objects.get(id=cipher_id, author=person)
    except:
        return HttpResponseRedirect("/")

    if request.method == "POST":

        tmp = request.POST["code"]
        cipher.programCode = tmp
        cipher.isReady = request.POST["vis"]=="true"
        cipher.save(force_update=True)

        return HttpResponse("OK")
    else:
        return render(request, "crypto_app/edit_cpp_cipher.html", {'cipher_name': cipher.name, "code": cipher.programCode, "ready":cipher.isReady, "id":cipher.id})


@csrf_exempt
def execute_python_cipher(request, cipher_id):
    try:
        cipher = PythonCipher.objects.get(id=cipher_id)
    except:
        return HttpResponseRedirect("/")

    if cipher.isReady == False:

        logged_in = request.session.get(AUTHENTICATED)
        if logged_in == None:
            logged_in = False
        else:
            logged_in = bool(logged_in)

        if not logged_in:
            return HttpResponseRedirect("/")

        uuid = request.session[USER_ID]
        person = Partipicant.objects.get(uuid=uuid)

        if cipher.author != person:
            return HttpResponseRedirect("/")

    if request.method == "POST":
        op = request.POST["op"]
        arg = request.POST["arg"]
        key = request.POST["key"]

        #Create a secomp sandbox
        r, w = os.pipe()
        r, w = os.fdopen(r, 'rb', 0), os.fdopen(w, 'wb', 0)

        newpid = os.fork()
        if newpid == 0:
            # Child
            r.close()
            sys.stdout.close()
            sys.stderr.close()
            sys.stdin.close()

            # Enforce timeout
            def timeout_handler(signum, frame):
                raise Exception("Execution of cipher timed out")

            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(10)

            #Enable seccomp
            #prctl.set_seccomp(True)

            try:
                if op == "enc":
                    res = cipher.getEncFun()(arg, key)
                    if type(res) is not str:
                        w.write(json.dumps({"res": "", "error": "Encryption function returned invalid type! Return type: {}".format(str(type(res)))}).encode('utf-8'))
                    else:
                        w.write(json.dumps({"res": res, "error": ""}).encode('utf-8'))
                elif op == "dec":
                    res = cipher.getDecFun()(arg, key)
                    if type(res) is not str:
                        w.write(json.dumps({"res": "",
                                             "error": "Decryption function returned invalid type! Return type: {}".format(
                                                 str(type(res)))}).encode('utf-8'))
                    else:
                        w.write(json.dumps({"res": res, "error": ""}).encode('utf-8'))
                else:
                    pass
            except SyntaxError as e:
                err = (''.join(traceback.format_exception_only(type(e), e)))
                w.write(json.dumps({"res": "", "error": err}).encode('utf-8'))
            except NameError as e:
                (exc_type, exc_value, exc_traceback) = sys.exc_info()
                tb_list = traceback.extract_tb(exc_traceback)
                tb_list = '\n'.join(traceback.format_list(tb_list)[1:])
                err = ''.join(traceback.format_exception_only(type(e), e))
                err += tb_list.__str__()
                w.write(json.dumps({"res": "", "error": err}).encode('utf-8'))
            except ValueError as e:
                (exc_type, exc_value, exc_traceback) = sys.exc_info()
                tb_list = traceback.extract_tb(exc_traceback)
                tb_list = '\n'.join(traceback.format_list(tb_list)[1:])
                err = ''.join(traceback.format_exception_only(type(e), e))
                err += tb_list.__str__()

                w.write(json.dumps({"res": "", "error": err}).encode('utf-8'))
            except Exception as e:
                w.write(json.dumps({"res": "", "error": "Your code broke something:\n" + str(e)+"\n\n\n"+traceback.format_exc()}).encode('utf-8'))

            signal.alarm(0)
            w.flush()
            return 0
        else:
            # Parent
            w.close()
            child_data = b""
            # Read from the child until the child is killed
            while 1:
                data = r.read()
                if not data: break
                child_data += data
            if child_data == b"":
                return JsonResponse({"res":"", "error":"A fatal exception occured"})
            return HttpResponse(child_data.decode("utf-8"))

    else:
        return HttpResponseRedirect("/edit_python_cipher/{}".format(cipher_id))


@csrf_exempt
def execute_js_cipher(request, cipher_id):
    try:
        cipher = JSCipher.objects.get(id=cipher_id)
    except:
        return HttpResponseRedirect("/")

    if cipher.isReady == False:

        logged_in = request.session.get(AUTHENTICATED)
        if logged_in == None:
            logged_in = False
        else:
            logged_in = bool(logged_in)

        if not logged_in:
            return HttpResponseRedirect("/")

        uuid = request.session[USER_ID]
        person = Partipicant.objects.get(uuid=uuid)

        if cipher.author != person:
            return HttpResponseRedirect("/")

    if request.method == "POST":
        op = request.POST["op"]
        arg = request.POST["arg"]
        key = request.POST["key"]

        #Create a secomp sandbox
        r, w = os.pipe()
        r, w = os.fdopen(r, 'rb', 0), os.fdopen(w, 'wb', 0)

        newpid = os.fork()
        if newpid == 0:
            # Child
            r.close()
            sys.stdout.close()
            sys.stderr.close()
            sys.stdin.close()

            #Enforce timeout
            def timeout_handler(signum, frame):
                raise Exception("Execution of cipher timed out")

            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(10) #10 seconds

            #Enable seccomp
            #prctl.set_seccomp(True)

            try:
                ctx = py_mini_racer.MiniRacer()
                res = None
                if op == "enc":
                    ctx.eval(cipher.encryptFun)
                    res = ctx.call("enc", arg, key)
                elif op == "dec":
                    ctx.eval(cipher.decryptFun)
                    res = ctx.call("dec", arg, key)

                if type(res) is not str:
                    w.write(json.dumps({"res": "",
                                        "error": "Function returned invalid type! Return type: {}".format(
                                            str(type(res)))}).encode('utf-8'))
                else:
                    w.write(json.dumps({"res": res, "error": ""}).encode('utf-8'))

            except Exception as e:
                w.write(json.dumps({"res": "", "error": "Your code broke something:\n" + str(e)}).encode('utf-8'))

            w.flush()
            signal.alarm(0)
            return 0

        else:
            # Parent
            w.close()
            child_data = b""
            # Read from the child until the child is killed
            while 1:
                data = r.read()
                if not data: break
                child_data += data
            if child_data == b"":
                return JsonResponse({"res":"", "error":"A fatal exception occured"})
            return HttpResponse(child_data.decode("utf-8"))

    else:
        return HttpResponseRedirect("/edit_js_cipher/{}".format(cipher_id))

@csrf_exempt
def execute_cpp_cipher(request, cipher_id):
    try:
        cipher = CPPCipher.objects.get(id=cipher_id)
    except:
        return HttpResponseRedirect("/")

    if cipher.isReady == False:

        logged_in = request.session.get(AUTHENTICATED)
        if logged_in == None:
            logged_in = False
        else:
            logged_in = bool(logged_in)

        if not logged_in:
            return HttpResponseRedirect("/")

        uuid = request.session[USER_ID]
        person = Partipicant.objects.get(uuid=uuid)

        if cipher.author != person:
            return HttpResponseRedirect("/")

    if request.method == "POST":
        op = request.POST["op"]
        arg = request.POST["arg"]
        key = request.POST["key"]

        #Create a secomp sandbox
        r, w = os.pipe()
        r, w = os.fdopen(r, 'rb', 0), os.fdopen(w, 'wb', 0)

        newpid = os.fork()
        if newpid == 0:
            # Child
            r.close()
            sys.stdout.close()
            sys.stderr.close()
            sys.stdin.close()

            #Enforce timeout
            def timeout_handler(signum, frame):
                raise Exception("Execution of cipher timed out")

            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(10) #10 seconds

            #Enable seccomp
            #prctl.set_seccomp(True)

            try:
                #compile the cipher
                random.seed()
                rand_name = ''.join([random.choice(string.digits) for _ in range(10)])
                with open("/tmp/"+rand_name+".cpp", "w") as f:
                    f.write(cipher.programCode)

                p = subprocess.Popen(['g++', '-std=c++11', '-O3', '-o', '/tmp/'+rand_name, '/tmp/'+rand_name+".cpp"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                return_code = p.wait()
                err = p.stdout.read()+p.stderr.read()
                err = err.decode('utf-8')
                err = err.replace("/tmp/"+rand_name+".cpp:", "program.cpp:")

                #remove program source
                os.remove("/tmp/"+rand_name+".cpp")

                if return_code != 0:
                    w.write(json.dumps({"res": "", "error": err}).encode('utf-8'))
                else:
                    if op == "enc" or op == "dec":
                        p = subprocess.Popen(
                            ['/tmp/' + rand_name, op, arg, key],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                        return_code = p.wait()
                        os.remove("/tmp/"+rand_name)
                        if return_code == 0:
                            res = p.stdout.read().decode('utf-8')
                            w.write(json.dumps({"res": res, "error": ""}).encode('utf-8'))
                        else:
                            err = p.stderr.read().decode('utf-8')
                            w.write(json.dumps({"res": "", "error": "Program execution failed. Exit code was {}. STDERR was {}".format(return_code, err)}).encode('utf-8'))
                    else:
                        pass
            except Exception as e:
                w.write(json.dumps({"res": "", "error": "Your code broke something:\n" + str(e)}).encode('utf-8'))

            w.flush()
            signal.alarm(0)
            return 0

        else:
            # Parent
            w.close()
            child_data = b""
            # Read from the child until the child is killed
            while 1:
                data = r.read()
                if not data: break
                child_data += data
            if child_data == b"":
                return JsonResponse({"res":"", "error":"A fatal exception occured"})
            return HttpResponse(child_data.decode("utf-8"))

    else:
        return HttpResponseRedirect("/edit_cpp_cipher/{}".format(cipher_id))

@never_cache
def play_with_cipher(request):
    logged_in = request.session.get(AUTHENTICATED)
    if logged_in == None:
        logged_in = False
    else:
        logged_in = bool(logged_in)

    if not logged_in:
        return HttpResponseRedirect("/")

    try:
        api = request.GET["api"]
    except:
        return HttpResponseRedirect("/")

    enc = ""
    dec = ""
    id = int(api.split("/")[-1])
    only_one = False
    if "python" in api:
        try:
            cipher = PythonCipher.objects.get(id=id, isReady=True)
            enc = cipher.encryptFun
            dec = cipher.decryptFun
        except:
            return HttpResponseRedirect("/")
    elif "js" in api:
        try:
            cipher = JSCipher.objects.get(id=id, isReady=True)
            enc = cipher.encryptFun
            dec = cipher.decryptFun
        except:
            return HttpResponseRedirect("/")
    elif "cpp" in api:
        try:
            cipher = CPPCipher.objects.get(id=id, isReady=True)
            only_one = True
            enc = cipher.programCode
        except:
            return  HttpResponseRedirect("/")


    return render(request, "crypto_app/play_with_cipher.html",{"api": api, "enc": enc, "dec": dec, "only_one": only_one})
