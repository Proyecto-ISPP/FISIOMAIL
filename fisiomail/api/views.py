from rest_framework.views import APIView
from rest_framework.response import Response
from api.models import EmailDataSerializer
from django.core.mail import EmailMessage
from rest_framework import status
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from django.conf import settings
from cryptography.hazmat.primitives import padding
from django.core.mail import send_mail
import base64
import os
from rest_framework.decorators import api_view
import random


class SendEmailAPI(APIView):
    def post(self, request, *args, **kwargs):
        # Verificar la API Key en la cabecera de la solicitud
        api_key = request.headers.get("X-API-Key")
        if api_key != settings.API_KEY:
            return Response({"detail": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        # Deserializar los datos cifrados
        serializer = EmailDataSerializer(data=request.data)
        if serializer.is_valid():
            # Extraer los datos cifrados
            encrypted_subject = serializer.validated_data['encrypted_subject']
            encrypted_recipient = serializer.validated_data['encrypted_recipient']
            encrypted_body = serializer.validated_data['encrypted_body']

            # Desencriptar los datos
            subject = self.decrypt_data(encrypted_subject)
            recipient = self.decrypt_data(encrypted_recipient)
            body = self.decrypt_data(encrypted_body)
            # Aquí puedes proceder a enviar el correo con Django (django.core.mail)
            # Enviar correo (usando Django Mail)

            email = EmailMessage(
                subject=subject,
                body=body,
                from_email=f'Fisio Find <{settings.EMAIL_HOST_USER}>',
                to=[recipient],
            )
            email.content_subtype = "html"
            email.extra_headers = {
                'Content-Transfer-Encoding': '8bit',
                'Content-Type': 'text/html; charset=UTF-8',
                'Reply-To': 'citas@fisiofind.com',
                'X-Mailer': 'FisioMail v1.0',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'List-Unsubscribe': 'mailto:unsubscribe@fisiofind.com',
            }
            email.send()
            return Response(status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def decrypt_data(self, encrypted_data):
        # Desencriptar los datos utilizando la clave del entorno (AES)
        key = bytes.fromhex(settings.ENCRYPTION_KEY)  # La clave de cifrado

        # Convertir los datos cifrados de base64
        encrypted_data_bytes = base64.b64decode(encrypted_data)

        # Extraer el IV (primeros 16 bytes de los datos cifrados)
        iv = encrypted_data_bytes[:16]  # El IV está al principio
        # Los datos cifrados están después del IV
        encrypted_data_bytes = encrypted_data_bytes[16:]

        # Desencriptar usando AES (Cifrado simétrico)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        # Desencriptar los datos
        decrypted_data = decryptor.update(
            encrypted_data_bytes) + decryptor.finalize()

        # Eliminar el padding con PKCS7
        unpadder = padding.PKCS7(128).unpadder()  # 128 bits = 16 bytes
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data.decode('utf-8')
