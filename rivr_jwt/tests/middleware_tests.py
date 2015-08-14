import unittest
from rivr.http import Request, Response
from rivr_jwt import JWTMiddleware


class JWTMiddlewareTests(unittest.TestCase):
    def setUp(self):
        self.middleware = JWTMiddleware(key='secret')
        self.jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiS3lsZSJ9.zxm7xcp1eZtZhp4t-nlw09ATQnnFKIiSN83uG8u6cAg'

    def test_sets_jwt_to_none_when_not_provided(self):
        request = Request()
        self.middleware.process_request(request)

        self.assertEqual(request.jwt, None)

    def test_decodes_request_authorization_header(self):
        request = Request(headers={'AUTHORIZATION': 'Bearer {}'.format(self.jwt)})
        self.middleware.process_request(request)

        self.assertEqual(request.jwt, {'name': 'Kyle'})

    # Cookies

    def test_decodes_request_cookie(self):
        request = Request()
        request.COOKIES = {'jwt': self.jwt}
        self.middleware.process_request(request)

        self.assertEqual(request.jwt, {'name': 'Kyle'})

    def test_encodes_jwt_in_cookie(self):
        response = Response()
        response.jwt_cookie = {'name': 'Kyle'}
        response = self.middleware.process_response(None, response)

        self.assertEqual(response.cookies['jwt'].value, self.jwt)

    def test_deletes_jwt_from_cookies_when_unset(self):
        response = Response()
        response.jwt_cookie = None
        response = self.middleware.process_response(None, response)

        self.assertEqual(response.cookies['jwt'].value, '')
        self.assertEqual(response.cookies['jwt']['expires'], 'Thu, 01-Jan-1970 00:00:00 GMT')

