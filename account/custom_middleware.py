import requests
import jwt
from jwt.algorithms import RSAAlgorithm
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
from django.contrib.auth import get_user_model

class MicrosoftGraphIDTokenAuthentication(BaseAuthentication):
    
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization', '').split()

        if len(auth_header) != 2 or auth_header[0].lower() != 'bearer':
            return None

        access_token = auth_header[1]

        try:
            header = jwt.get_unverified_header(access_token)
            
            # Check if the token is from Microsoft (for example, check 'iss' field)
            unverified_payload = jwt.decode(access_token, options={"verify_signature": False})
            if not unverified_payload.get('iss', '').startswith('https://login.microsoftonline.com/'):
                # Not a Microsoft token, so skip this authentication
                return None


            client_id = '12de49a4-a9ff-41cb-9ad8-c7021dbf6073'
            tenant_id = 'a6c3ca3f-6273-4fcb-bc66-9c7caa72a951'
            authority = f'https://login.microsoftonline.com/{tenant_id}'
            jwks_url = f'{authority}/discovery/v2.0/keys'

            kid = header.get('kid')
            jwks_response = requests.get(jwks_url)
            jwks = jwks_response.json()
            
            public_key = None
            for key in jwks['keys']:
                if key['kid'] == kid:
                    public_key = RSAAlgorithm.from_jwk(key)
                    break
            
            if public_key == None:
                raise AuthenticationFailed("Public key not found.")

            # Verify the JWT using the PEM formatted public key
            decoded_token = jwt.decode(
                access_token,
                public_key,
                algorithms=['RS256'],
                audience=client_id  # Ensure audience matches your Azure AD App Registration
            )

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidAudienceError:
            raise AuthenticationFailed('Invalid audience: The audience claim does not match your client ID')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token: Signature verification failed!')
        except Exception as e:
            print('Error:', str(e))
            raise AuthenticationFailed('Error:', str(e))

        # Implement user retrieval or creation logic here if necessary
        user_email = decoded_token.get('preferred_username')
        if not user_email:
            raise AuthenticationFailed('Invalid token payload!')

        # Assume user model has email as username
        User = get_user_model()

        try:
            user = User.objects.get(email=user_email)
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found.')

        return (user, None)
