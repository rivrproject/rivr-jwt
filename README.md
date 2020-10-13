# rivr-jwt

A library for using JSON Web Tokens (JWT) for authentication with [rivr](https://github.com/rivrproject/rivr).

## Installation

```bash
$ pip install rivr-jwt
```

## Usage

rivr-jwt provides a middleware which can automatically verify JSON Web Tokens
from both cookies and Authorization headers, the JWT payload will be available
as `jwt` on the request object passed though the JWT middleware.

```python
middleware = JWTMiddleware(key='secret', algorithms=['HS256'])
```

### Using a JWT from a Cookie or Authorization header

```python
def view(request):
    if request.jwt and 'username' in request.jwt:
        username = request.jwt['username']
        return Response('Hello {}'.format(username))

    return Response('Hello world')
```

### Setting JWT as a cookie

You can set `jwt_cookie` on a response for it to be encoded as a cookie.

```python
def view(request):
    response = Response('Hello World')
    response.jwt_cookie = {'username': 'Kyle'}
    return response
```

## License

rivr-rest is released under the BSD license. See [LICENSE](LICENSE).

