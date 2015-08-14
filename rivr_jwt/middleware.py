import jwt
from rivr import Middleware


class JWTMiddleware(Middleware):
    algorithms = ('HS256',)
    key = None

    cookie_name = 'jwt'
    cookie_secure = False

    header_name = 'AUTHORIZATION'
    header_grant_type = 'Bearer'

    def create_jwt(self, payload):
        """
        Creates a JWT from the given payload.
        """
        return jwt.encode(payload, self.key, algorithm=self.algorithms[0])

    def verify_jwt(self, encoded_jwt):
        """
        Verifies the given JWT token, returning the decoded object, or None.
        """
        return jwt.decode(encoded_jwt, self.key, algorithms=self.algorithms)

    def process_request(self, request):
        request.browserid_middleware = self

        if self.header_name in request.headers:
            bearer, token = request.headers[self.header_name].split(' ', 1)
            request.jwt = self.verify_jwt(token)
        elif getattr(request, 'COOKIES', None) and self.cookie_name in request.COOKIES:
            request.jwt = self.verify_jwt(request.COOKIES[self.cookie_name])
        else:
            request.jwt = None

    def process_response(self, request, response):
        if hasattr(response, 'jwt_cookie'):
            if response.jwt_cookie:
                encoded_jwt = self.create_jwt(response.jwt_cookie)
                response.set_cookie(self.cookie_name, encoded_jwt, secure=self.cookie_secure)
            else:
                response.delete_cookie(self.cookie_name)

        return response

