from django.db import models
from rest_framework import serializers

# Create your models here.
class EmailDataSerializer(serializers.Serializer):
    encrypted_subject = serializers.CharField()
    encrypted_recipient = serializers.CharField()
    encrypted_body = serializers.CharField()