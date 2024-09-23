# middleware.py

import jwt
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.conf import settings

class APIAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get the Authorization header from the request
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing.'}, status=401)

        # Split the header to get the token (assuming format is 'Bearer <token>')
        try:
            token_type, token = auth_header.split(' ')
            if token_type.lower() != 'bearer':
                raise ValueError('Invalid token type')
        except ValueError:
            return JsonResponse({'error': 'Invalid Authorization header format.'}, status=401)

        # Example: Decode a JWT token (replace with your token verification logic)
        try:
            # Assuming the secret key is stored in Django settings
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            # Assuming the payload contains the username
            user = User.objects.get(username=payload['username'])
            request.user = user
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token has expired.'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid token.'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User does not exist.'}, status=401)

        # Call the next middleware or view
        response = self.get_response(request)
        return response
