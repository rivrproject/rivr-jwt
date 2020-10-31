import pytest
from jwt.exceptions import (
    InvalidAudienceError,
    InvalidIssuerError,
    MissingRequiredClaimError,
)

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


def test_process_request_allows_matching_audience():
    jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJleGFtcGxlLmNvbSJ9.INovSA2CyXeBwzR0Bqq-pFuxfQLVgnFpN4x1JP0Ve84'
    middleware = JWTMiddleware(key='secret', audience=['example.com'])
    request = Request(headers={'Authorization': 'Bearer {}'.format(jwt)})
    middleware.process_request(request)

    assert request.jwt == {'aud': 'example.com'}


def test_process_request_disallows_missing_audience(jwt):
    middleware = JWTMiddleware(key='secret', audience='prod.example.com')
    request = Request(headers={'Authorization': 'Bearer {}'.format(jwt)})

    with pytest.raises(MissingRequiredClaimError):
        middleware.process_request(request)

    assert request.jwt == None


def test_process_request_disallows_incorrect_audience():
    jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJleGFtcGxlLmNvbSJ9.INovSA2CyXeBwzR0Bqq-pFuxfQLVgnFpN4x1JP0Ve84'
    middleware = JWTMiddleware(key='secret', audience='prod.example.com')
    request = Request(headers={'Authorization': 'Bearer {}'.format(jwt)})

    with pytest.raises(InvalidAudienceError):
        middleware.process_request(request)

    assert request.jwt == None


def test_process_request_calls_401_for_invalid_token():
    jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJleGFtcGxlLmNvbSJ9.INovSA2CyXeBwzR0Bqq-pFuxfQLVgnFpN4x1JP0Ve84'
    middleware = JWTMiddleware(key='secret', audience='prod.example.com')
    middleware.custom_401 = lambda r: Response('custom 401')

    request = Request(headers={'Authorization': 'Bearer {}'.format(jwt)})
    response = middleware.process_request(request)

    assert response.content == 'custom 401'
    assert request.jwt == None


def test_process_request_allows_matching_issuer():
    jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJleGFtcGxlLmNvbSJ9.c2lmFOiVCSRyegrYJjx60BzBhacHt3BZ-avr4PtGqWk'
    middleware = JWTMiddleware(key='secret', issuer='example.com')
    request = Request(headers={'Authorization': 'Bearer {}'.format(jwt)})
    middleware.process_request(request)

    assert request.jwt == {'iss': 'example.com'}


def test_process_request_disallows_missing_issuer(jwt):
    middleware = JWTMiddleware(key='secret', issuer='example.com')
    request = Request(headers={'Authorization': 'Bearer {}'.format(jwt)})

    with pytest.raises(MissingRequiredClaimError):
        middleware.process_request(request)

    assert request.jwt == None


def test_process_request_disallows_incorrect_issuer():
    jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJleGFtcGxlLmNvbSJ9.c2lmFOiVCSRyegrYJjx60BzBhacHt3BZ-avr4PtGqWk'
    middleware = JWTMiddleware(key='secret', issuer='prod.example.com')
    request = Request(headers={'Authorization': 'Bearer {}'.format(jwt)})

    with pytest.raises(InvalidIssuerError):
        middleware.process_request(request)

    assert request.jwt == None


def test_process_request_decodes_cookie(middleware, jwt):
    request = Request()
    request.cookies['jwt'] = jwt
    middleware.process_request(request)

    assert request.jwt == {'name': 'Kyle'}


def test_process_request_ignores_invalid_cookie(middleware, jwt):
    request = Request()
    request.cookies['jwt'] = 'a.b.c'
    middleware.process_request(request)

    assert request.jwt is None


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
