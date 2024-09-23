from django.shortcuts import render

# Create your views here.
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import authentication_classes
from account.custom_middleware import MicrosoftGraphIDTokenAuthentication

@authentication_classes([MicrosoftGraphIDTokenAuthentication, JWTAuthentication])
class ExampleView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        content = {'message': 'You are authenticated, '+ user.email }
        return Response(content)