from django.urls import path
from .views import SendEmailAPI

urlpatterns = [
    path('send', SendEmailAPI.as_view(), name='send-email'),
]
