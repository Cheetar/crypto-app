from django.urls import path
from django.conf.urls.static import static
from django.conf import settings

from . import views


urlpatterns = [
    path("", views.index),
    path("register", views.register),
    path("logout", views.logout),
    path("login", views.login),
    path("newcipher", views.newcipher),
    path("edit_python_cipher/<int:cipher_id>", views.edit_python_cipher),
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

