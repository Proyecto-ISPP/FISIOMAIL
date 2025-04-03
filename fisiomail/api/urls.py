from django.urls import path
from .views import SendEmailAPI
from api import views

urlpatterns = [
    path('send', SendEmailAPI.as_view(), name='send-email'),
]
