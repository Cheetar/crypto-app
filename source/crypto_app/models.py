from django.db import models
import uuid

# The list of symbols that are included by default in the generated
# function's environment
SAFE_SYMBOLS = ["list", "dict", "tuple", "set", "long", "float", "object",
                "bool", "callable", "True", "False", "dir",
                "frozenset", "getattr", "hasattr", "abs", "cmp", "complex",
                "divmod", "id", "pow", "round", "slice", "vars",
                "hash", "hex", "int", "isinstance", "issubclass", "len",
                "map", "filter", "max", "min", "oct", "chr", "ord", "range",
                "reduce", "repr", "str", "type", "zip", "xrange", "None",
                "Exception", "KeyboardInterrupt", "class"]
# Also add the standard exceptions
__bi = __builtins__
if type(__bi) is not dict:
    __bi = __bi.__dict__
for k in __bi:
    if k.endswith("Error") or k.endswith("Warning"):
        SAFE_SYMBOLS.append(k)
del __bi

def createFunction(function_name, sourceCode, additional_symbols=dict()):
    # Include the sourcecode as the code of a function __TheFunction__:
    s = sourceCode

    # Byte-compilation (optional)
    byteCode = compile(s, "<string>", 'exec')

    # Setup the local and global dictionaries of the execution
    # environment for __TheFunction__
    bis = dict()  # builtins
    globs = dict()
    locs = dict()

    # Setup a standard-compatible python environment
    bis["locals"] = lambda: locs
    bis["globals"] = lambda: globs
    globs["__builtins__"] = bis
    globs["__name__"] = "SUBENV"
    globs["__doc__"] = sourceCode

    # Determine how the __builtins__ dictionary should be accessed
    if type(__builtins__) is dict:
        bi_dict = __builtins__
    else:
        bi_dict = __builtins__.__dict__

    # Include the safe symbols
    for k in SAFE_SYMBOLS:
        # try from current locals
        try:
            locs[k] = locals()[k]
            continue
        except KeyError:
            pass
        # Try from globals
        try:
            globs[k] = globals()[k]
            continue
        except KeyError:
            pass
        # Try from builtins
        try:
            bis[k] = bi_dict[k]
        except KeyError:
            # Symbol not available anywhere: silently ignored
            pass

    # Include the symbols added by the caller, in the globals dictionary
    globs.update(additional_symbols)

    # Finally execute the def __TheFunction__ statement:
    eval(byteCode, globs, locs)
    # As a result, the function is defined as the item __TheFunction__
    # in the locals dictionary
    fct = locs[function_name]
    # Attach the function to the globals so that it can be recursive
    del locs[function_name]
    globs[function_name] = fct
    # Attach the actual source code to the docstring
    fct.__doc__ = sourceCode
    return fct


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

    def getEncFun(self):
        return createFunction("enc", self.encryptFun)

    def getDecFun(self):
        return createFunction("dec", self.decryptFun)

class JSCipher(models.Model):
    name = models.TextField()
    isReady = models.BooleanField(default=False)

    encryptFun = models.TextField(blank=True)
    decryptFun = models.TextField(blank=True)

    author = models.ForeignKey('Partipicant', on_delete=models.CASCADE, )

class CPPCipher(models.Model):
    name = models.TextField()
    isReady = models.BooleanField(default=False)

    programCode = models.TextField(blank=True)

    author = models.ForeignKey('Partipicant', on_delete=models.CASCADE, )
