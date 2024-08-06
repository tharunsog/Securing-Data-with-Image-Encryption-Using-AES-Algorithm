from django.urls import path, include
from .views import *


urlpatterns = [

    path('', index, name="index"),
    path('signup', signup, name="signup"),
    path('signin', signin, name="signin"),
    path('encryptdata', encryptdata, name="encryptdata"),
    path('hidedata', hidedata, name="hidedata"),
    path('performancegraph', performancegraph, name="performancegraph"),
    path('hidingimage', hidingimage, name="hidingimage"),
    path('filerequests', filerequests, name="filerequests"),
    path('sendrequest/<int:id>', sendrequest, name="sendrequest"),
    path('viewrequests', viewrequests, name="viewrequests"),
    path('sendkey/<int:id>/<int:fileid>', sendkey, name="sendkey"),
    path('decryptdata', decryptdata, name="decryptdata"),
]
