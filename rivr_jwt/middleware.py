from typing import Dict, Any, Optional, Sequence, Callable

import jwt
from jwt.exceptions import PyJWTError
from rivr import Middleware
from rivr.http import Request, Response


class JWTMiddleware(Middleware):
    algorithms = ('HS256',)
    key = None

    custom_401: Optional[Callable[[Request], Response]] = None

    audience: Optional[Sequence[str]] = None
    issuer: Optional[str] = None

    cookie_name = 'jwt'
    cookie_secure = False

    header_name = 'AUTHORIZATION'
    header_grant_type = 'Bearer'

    def create_jwt(self, payload: Dict[str, Any]):
        """
        Creates a JWT from the given payload.
        """
        if not self.key:
            raise Exception('Missing key')

        return jwt.encode(payload, self.key, algorithm=self.algorithms[0])

    def verify_jwt(self, encoded_jwt: str) -> Dict[Any, Any]:
        """
        Verifies the given JWT token, returning the decoded object, or None.
        """

        if not self.key:
            raise Exception('Missing key')

        return jwt.decode(
            encoded_jwt,
            self.key,
            audience=self.audience,
            issuer=self.issuer,
            algorithms=self.algorithms,
        )

    def process_request(self, request: Request) -> Optional[Response]:
        setattr(request, 'browserid_middleware', self)
        setattr(request, 'jwt', None)

        header = request.headers[self.header_name]
        if header:
            bearer, token = header.split(' ', 1)

            try:
                setattr(request, 'jwt', self.verify_jwt(token))
            except PyJWTError:
                if self.custom_401:
                    return self.custom_401(request)
                raise
        elif self.cookie_name in request.cookies:
            cookie = request.cookies[self.cookie_name].value

            try:
                setattr(request, 'jwt', self.verify_jwt(cookie))
            except PyJWTError:
                # ignore invalid cookies
                pass

        else:
            setattr(request, 'jwt', None)

        return None

    def process_response(self, request: Request, response: Response) -> Response:
        if hasattr(response, 'jwt_cookie'):
            jwt_cookie = getattr(response, 'jwt_cookie')
            if jwt_cookie:
                encoded_jwt = self.create_jwt(jwt_cookie)
                response.set_cookie(
                    self.cookie_name,
                    encoded_jwt.decode('utf-8'),
                    secure=self.cookie_secure,
                )
            else:
                response.delete_cookie(self.cookie_name)

        return response
