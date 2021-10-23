import datetime
import json
from typing import Any, Callable, Dict, Optional, Sequence, Tuple
from urllib.request import urlopen

import jwt
from jwt import InvalidTokenError, PyJWKSet
from jwt.api_jwt import decode_complete
from jwt.exceptions import PyJWTError
from rivr import Middleware
from rivr.http import Request, Response


class JWTMiddleware(Middleware):
    algorithms = ('HS256',)
    key = None

    jwks_uri = None

    custom_401: Optional[Callable[[Request], Response]] = None

    audience: Optional[Sequence[str]] = None
    issuer: Optional[str] = None

    cookie_name = 'jwt'
    cookie_secure = False

    header_name = 'AUTHORIZATION'
    header_grant_type = 'Bearer'

    def __init__(self, *args, **kwargs):
        self._jwks = None
        self._jwks_fetched_date = None

        super(JWTMiddleware, self).__init__(*args, **kwargs)

    def create_jwt(self, payload: Dict[str, Any]):
        """
        Creates a JWT from the given payload.
        """
        if not self.key:
            raise Exception('Configuration error: Missing key')

        return jwt.encode(payload, self.key, algorithm=self.algorithms[0])

    @property
    def is_jwks_expired(self) -> bool:
        assert self._jwks_fetched_date
        return (self._jwks_fetched_date + datetime.timedelta(hours=1)) < datetime.datetime.now()

    def get_jwks(self) -> PyJWKSet:
        if not self.jwks_uri:
            raise Exception('Configuration error: Missing key or jwks_uri')

        if not self._jwks or self.is_jwks_expired:
            with urlopen(self.jwks_uri) as fp:
                # FIXME perform retries
                self._jwks = PyJWKSet.from_dict(json.load(fp))
                self._jwks_fetched_date = datetime.datetime.now()

        return self._jwks

    def get_jwk(self, token: str) -> Tuple[Sequence[str], Any]:
        if self.key:
            return (self.algorithms, self.key)

        unverified = decode_complete(token, options={"verify_signature": False})
        kid = unverified['header'].get('kid')
        alg = unverified['header'].get('alg')
        if not kid:
            raise InvalidTokenError('No key ID')
        if not alg:
            raise InvalidTokenError('No alg')

        jwks = self.get_jwks()
        for key in jwks.keys:
            if key.key_id != kid:
                continue

            if key.public_key_use != 'sig':
                continue

            if alg != key._jwk_data.get('alg', None):
                continue

            return (key._jwk_data.get('alg'), key.key)

        raise InvalidTokenError('Unknown key')

    def verify_jwt(self, encoded_jwt: str) -> Dict[Any, Any]:
        """
        Verifies the given JWT token, returning the decoded object, or None.
        """

        (algorithms, key) = self.get_jwk(encoded_jwt)

        return jwt.decode(
            encoded_jwt,
            key,
            audience=self.audience,
            issuer=self.issuer,
            algorithms=algorithms,
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
                    encoded_jwt,
                    secure=self.cookie_secure,
                )
            else:
                response.delete_cookie(self.cookie_name)

        return response
