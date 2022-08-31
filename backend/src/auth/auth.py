import json
from os import abort
from six.moves.urllib.request import urlopen
from functools import wraps

from flask import Flask, request, jsonify, _request_ctx_stack
from flask_cors import cross_origin
from jose import jwt
# Error handler
AUTH0_DOMAIN = 'nazehs.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'dev'


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

# Format error response and append status code


def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header
    """
    # auth = request.headers.get("Authorization", None)
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                        "description":
                            "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must start with"
                            " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)

    token = parts[1]
    return token


# def requires_auth(f):
#     """Determines if the Access Token is valid
#     """
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = get_token_auth_header()
#         jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
#         jwks = json.loads(jsonurl.read())
#         unverified_header = jwt.get_unverified_header(token)
#         rsa_key = {}
#         for key in jwks["keys"]:
#             if key["kid"] == unverified_header["kid"]:
#                 rsa_key = {
#                     "kty": key["kty"],
#                     "kid": key["kid"],
#                     "use": key["use"],
#                     "n": key["n"],
#                     "e": key["e"]
#                 }
#         if rsa_key:
#             try:
#                 payload = jwt.decode(
#                     token,
#                     rsa_key,
#                     algorithms=ALGORITHMS,
#                     audience=API_AUDIENCE,
#                     issuer="https://"+AUTH0_DOMAIN+"/"
#                 )
#             except jwt.ExpiredSignatureError:
#                 raise AuthError({"code": "token_expired",
#                                 "description": "token is expired"}, 401)
#             except jwt.JWTClaimsError:
#                 raise AuthError({"code": "invalid_claims",
#                                 "description":
#                                     "incorrect claims,"
#                                     "please check the audience and issuer"}, 401)
#             except Exception:
#                 raise AuthError({"code": "invalid_header",
#                                 "description":
#                                     "Unable to parse authentication"
#                                     " token."}, 401)

#             _request_ctx_stack.top.current_user = payload
#             return f(*args, **kwargs)
#         raise AuthError({"code": "invalid_header",
#                         "description": "Unable to find appropriate key"}, 401)
#     return decorated

# import json
# from os import abort
# from flask import request, _request_ctx_stack
# from functools import wraps
# from jose import jwt
# from urllib.request import urlopen


# AUTH0_DOMAIN = 'nazehs.auth0.com'
# ALGORITHMS = ['RS256']
# API_AUDIENCE = 'dev'

# # AuthError Exception
# '''
# AuthError Exception
# A standardized way to communicate auth failure modes
# '''


# class AuthError(Exception):
#     def __init__(self, error, status_code):
#         self.error = error
#         self.status_code = status_code


# # Auth Header

# def get_token_auth_header():
#     """Obtains the Access Token from the Authorization Header
#     """
#     auth = request.headers.get('Authorization', None)
#     print(auth)
#     if not auth:
#         raise AuthError({
#             'code': 'authorization_header_missing',
#             'description': 'Authorization header is expected.'
#         }, 401)

#     parts = auth.split()
#     if parts[0].lower() != 'bearer':
#         raise AuthError({
#             'code': 'invalid_header',
#             'description': 'Authorization header must start with "Bearer".'
#         }, 401)

#     elif len(parts) == 1:
#         raise AuthError({
#             'code': 'invalid_header',
#             'description': 'Token not found.'
#         }, 401)

#     elif len(parts) > 2:
#         raise AuthError({
#             'code': 'invalid_header',
#             'description': 'Authorization header must be bearer token.'
#         }, 401)

#     token = parts[1]
#     return token


def verify_decode_jwt(token):
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
        'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
    }, 400)


def check_permissions(permission, payload):
    print(payload)
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 403)
    return True


def guard_auth(permission=''):
    def requires_auth_decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            try:
                payload = verify_decode_jwt(token)
            except:
                abort(401)

            check_permissions(permission, payload)
            return function(*args, **kwargs)
        return wrapper
    return requires_auth_decorator
