from aiohttp import web
import base64
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models import User


async def basic_auth_middleware(app, handler):
    async def middleware(request):
        if request.path.startswith('/register') or request.path.startswith('/ads') and request.method == 'GET':
            return await handler(request)

        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Basic '):
            return web.json_response({'error': 'Authorization required'}, status=401)

        try:
            encoded_credentials = auth_header.split(' ')[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            email, password = decoded_credentials.split(':', 1)

            session = request['db']
            result = await session.execute(select(User).filter(User.email == email))
            user = result.scalar_one_or_none()

            if not user or not user.check_password(password):
                return web.json_response({'error': 'Invalid credentials'}, status=401)

            request['user'] = user

        except (ValueError, IndexError, UnicodeDecodeError):
            return web.json_response({'error': 'Invalid authorization header'}, status=401)

        return await handler(request)

    return middleware