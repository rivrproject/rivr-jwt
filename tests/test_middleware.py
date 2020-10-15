import pytest

from rivr.http import Request, Response
from rivr_jwt import JWTMiddleware


@pytest.fixture
def middleware() -> JWTMiddleware:
    return JWTMiddleware(key='secret')


@pytest.fixture
def jwt() -> str:
    return 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiS3lsZSJ9.4tCpoxfyfjbUyLjm9_zu-r52Vxn6bFq9kp6Rt9xMs4A'


def test_process_request_sets_empty_jwt_when_none_provided(middleware):
    request = Request()
    middleware.process_request(request)

    assert request.jwt is None


def test_process_request_decodes_authorization_header(middleware, jwt):
    request = Request(headers={'Authorization': 'Bearer {}'.format(jwt)})
    middleware.process_request(request)

    assert request.jwt == {'name': 'Kyle'}


def test_process_request_decodes_cookie(middleware, jwt):
    request = Request()
    request.cookies['jwt'] = jwt
    middleware.process_request(request)

    assert request.jwt == {'name': 'Kyle'}


def test_process_response_encodes_cookie(middleware, jwt):
    response = Response()
    response.jwt_cookie = {'name': 'Kyle'}
    response = middleware.process_response(Request(), response)

    assert response.cookies['jwt'].value == jwt


def test_process_response_unsets_cookie(middleware, jwt):
    response = Response()
    response.jwt_cookie = None
    response = middleware.process_response(Request(), response)

    morsel = response.cookies['jwt']
    assert morsel.value == ''
    assert morsel['expires'] == 'Thu, 01-Jan-1970 00:00:00 GMT'
