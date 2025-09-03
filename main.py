import base64

from aiohttp import web
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from database import init_db, get_db
from models import User, Advertisement
from validators import AdvertisementCreateValidator, AdvertisementUpdateValidator, UserCreateValidator
from auth import basic_auth_middleware
import json


async def init_app():
    app = web.Application()

    # Инициализация базы данных
    await init_db()

    # Добавляем middleware в правильном порядке
    app.middlewares.append(db_middleware)
    app.middlewares.append(basic_auth_middleware)

    # Добавление routes
    app.router.add_post('/register/', register_user)
    app.router.add_get('/ads/', get_advertisements)
    app.router.add_get('/ads/{ad_id}/', get_advertisement)
    app.router.add_post('/ads/', create_advertisement)
    app.router.add_patch('/ads/{ad_id}/', update_advertisement)
    app.router.add_delete('/ads/{ad_id}/', delete_advertisement)

    return app


@web.middleware
async def db_middleware(request, handler):
    async for session in get_db():
        request['db'] = session
        try:
            response = await handler(request)
            return response
        finally:
            pass
    return await handler(request)


@web.middleware
async def basic_auth_middleware(request, handler):
    if request.path.startswith('/register') or (request.path.startswith('/ads') and request.method == 'GET'):
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


async def register_user(request):
    session = request['db']
    try:
        data = await request.json()
        validated_data = UserCreateValidator(**data).model_dump()

        # Проверяем, существует ли пользователь
        result = await session.execute(select(User).filter(User.email == validated_data['email']))
        if result.scalar_one_or_none():
            return web.json_response({'error': 'User with this email already exists'}, status=400)

        user = User(email=validated_data['email'])
        user.set_password(validated_data['password'])

        session.add(user)
        await session.commit()

        return web.json_response({
            'message': 'User created successfully',
            'user_id': user.id
        }, status=201)

    except Exception as e:
        return web.json_response({'error': str(e)}, status=400)


async def get_advertisements(request):
    session = request['db']
    result = await session.execute(select(Advertisement))
    advertisements = result.scalars().all()

    return web.json_response([ad.to_dict() for ad in advertisements])


async def get_advertisement(request):
    session = request['db']
    ad_id = int(request.match_info['ad_id'])

    result = await session.execute(select(Advertisement).filter(Advertisement.id == ad_id))
    advertisement = result.scalar_one_or_none()

    if not advertisement:
        return web.json_response({'error': 'Advertisement not found'}, status=404)

    return web.json_response(advertisement.to_dict())


async def create_advertisement(request):
    session = request['db']
    user = request.get('user')

    if not user:
        return web.json_response({'error': 'Authentication required'}, status=401)

    try:
        data = await request.json()
        validated_data = AdvertisementCreateValidator(**data).model_dump()

        advertisement = Advertisement(
            title=validated_data['title'],
            description=validated_data['description'],
            owner_id=user.id
        )

        session.add(advertisement)
        await session.commit()

        return web.json_response(advertisement.to_dict(), status=201)

    except Exception as e:
        return web.json_response({'error': str(e)}, status=400)


async def update_advertisement(request):
    session = request['db']
    user = request.get('user')
    ad_id = int(request.match_info['ad_id'])

    if not user:
        return web.json_response({'error': 'Authentication required'}, status=401)

    result = await session.execute(select(Advertisement).filter(Advertisement.id == ad_id))
    advertisement = result.scalar_one_or_none()

    if not advertisement:
        return web.json_response({'error': 'Advertisement not found'}, status=404)

    if advertisement.owner_id != user.id:
        return web.json_response({'error': 'You can only edit your own advertisements'}, status=403)

    try:
        data = await request.json()
        validated_data = AdvertisementUpdateValidator(**data).model_dump(exclude_none=True)

        if 'title' in validated_data:
            advertisement.title = validated_data['title']
        if 'description' in validated_data:
            advertisement.description = validated_data['description']

        await session.commit()

        return web.json_response(advertisement.to_dict())

    except Exception as e:
        return web.json_response({'error': str(e)}, status=400)


async def delete_advertisement(request):
    session = request['db']
    user = request.get('user')
    ad_id = int(request.match_info['ad_id'])

    if not user:
        return web.json_response({'error': 'Authentication required'}, status=401)

    result = await session.execute(select(Advertisement).filter(Advertisement.id == ad_id))
    advertisement = result.scalar_one_or_none()

    if not advertisement:
        return web.json_response({'error': 'Advertisement not found'}, status=404)

    if advertisement.owner_id != user.id:
        return web.json_response({'error': 'You can only delete your own advertisements'}, status=403)

    await session.delete(advertisement)
    await session.commit()

    return web.json_response({'message': 'Advertisement deleted successfully'})


if __name__ == '__main__':
    web.run_app(init_app(), host='127.0.0.1', port=5000)