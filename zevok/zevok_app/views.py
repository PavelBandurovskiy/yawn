import base64
import httpx
import json

import datetime
from django.shortcuts import render
from django.utils import timezone
from django.utils.dateformat import format

from django.contrib.auth import logout
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from .forms import LoginForm, UpdateUserForm
from .forms import RegisterForm
from django.shortcuts import render, redirect
from django.contrib import messages
from asgiref.sync import sync_to_async


USER_IDS = []
async def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if await sync_to_async(form.is_valid)():
            user_data = {
                'email': None,
                'password': None,
                'newEmail': form.cleaned_data['newEmail'],
                'newName': form.cleaned_data['newName'],
                'newPassword': form.cleaned_data['newPassword'],
            }
            encoded_data = base64.b64encode(json.dumps(user_data).encode()).decode()

            print(f"\n\n{user_data}\n\n")

            url = 'http://localhost:8081/api/users'
            print("Отправка запроса на URL:", url)
            print("Отправляемые данные:", user_data)
            print("Заголовок Authorization:", encoded_data)

            async with httpx.AsyncClient() as client:
                try:
                    response = await client.post(url, headers={'Authorization': encoded_data})
                    print("Запрос отправлен. Статус ответа:", response.status_code)
                    print("Ответ сервера:", response.text)

                    if response.status_code == 200:
                        user_info = response.json()
                        await sync_to_async(request.session.__setitem__)('user_id', user_info['id'])
                        await sync_to_async(request.session.__setitem__)('user_name', user_info['name'])
                        await sync_to_async(request.session.__setitem__)('user_email', user_info['email'])
                        await sync_to_async(request.session.__setitem__)('password', user_data['newPassword'])
                        await sync_to_async(messages.success)(request, 'Регистрация прошла успешно!')
                        print("Регистрация выполнена успешно: Пользователь {}.".format(user_info['name']))

                        print("Данные сессии после регистрации:")
                        print(f"user_id: {await sync_to_async(request.session.get)('user_id')}")
                        print(f"user_name: {await sync_to_async(request.session.get)('user_name')}")
                        print(f"user_email: {await sync_to_async(request.session.get)('user_email')}")
                        print(f"user_email: {await sync_to_async(request.session.get)('password')}")

                        return await sync_to_async(redirect)(f'/user_profile/{user_info["id"]}/')
                    else:
                        await sync_to_async(messages.error)(request, 'Ошибка регистрации: ' + response.text)
                        print("Ошибка регистрации: Статус ответа {}.".format(response.status_code))
                except httpx.RequestError as exc:
                    print(f"Ошибка запроса: {exc}")
                except Exception as e:
                    print(f"Неожиданная ошибка: {str(e)}")
    else:
        form = RegisterForm()

    return await sync_to_async(render)(request, 'register.html', {'form': form})

async def login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if await sync_to_async(form.is_valid)():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']

            user_data = {
                'email': email,
                'password': password,
            }
            encoded_credentials = base64.b64encode(json.dumps(user_data).encode()).decode()

            login_url = 'http://localhost:8081/api/users/info'
            print("Отправка запроса на URL:", login_url)
            print("Заголовок Authorization:", f'{encoded_credentials}')

            async with httpx.AsyncClient() as client:
                try:
                    login_response = await client.get(
                        login_url,
                        headers={'Authorization': f'{encoded_credentials}'}
                    )
                    print(login_response.json())
                    print("Запрос отправлен. Статус ответа:", login_response.status_code)
                    print("Ответ сервера:", login_response.text)

                    if login_response.status_code == 200:
                        user_info = login_response.json()

                        await sync_to_async(request.session.__setitem__)('user_id', user_info['id'])
                        await sync_to_async(request.session.__setitem__)('user_name', user_info['name'])
                        await sync_to_async(request.session.__setitem__)('user_email', user_info['email'])
                        await sync_to_async(request.session.__setitem__)('password', user_data['password'])
                        #

                        print(f"user_pass: {await sync_to_async(request.session.get)('password')}")
                        print("Данные сессии после входа:")
                        print(f"user_id: {await sync_to_async(request.session.get)('user_id')}")
                        print(f"user_name: {await sync_to_async(request.session.get)('user_name')}")
                        print(f"user_email: {await sync_to_async(request.session.get)('user_email')}")

                        await sync_to_async(messages.success)(request, 'Вход выполнен успешно!')
                        return HttpResponseRedirect(f'/user_profile/{user_info["id"]}')
                    else:
                        await sync_to_async(messages.error)(request, f'Ошибка входа: {login_response.text}')
                        print(f"Ошибка входа: Статус ответа {login_response.status_code}")
                except httpx.RequestError as exc:
                    print(f"Ошибка запроса: {exc}")
                except Exception as e:
                    print(f"Неожиданная ошибка: {str(e)}")
    else:
        form = LoginForm()

    return await sync_to_async(render)(request, 'login.html', {'form': form})

async def get_user_info(request, id=None):
    user_id = await sync_to_async(request.session.get)('user_id')
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    print(f'login {user_pass}')

    if not user_email:
        messages.error(request, 'Вы не авторизованы. Пожалуйста, войдите в систему.')
        return redirect('login')

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    print(user_data)
    token = base64.b64encode(json.dumps(user_data).encode()).decode()
    print(token)

    if id is not None:
        user_info_url = f'http://localhost:8081/api/users/{id}'
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(user_info_url, headers={'Authorization': token})
                if response.status_code == 200:
                    user_info = response.json()
                    friends = await get_several_friends(request, 3)
                    return render(request, 'user_profile.html', {
                        'user': user_info,
                        'current_user_id': user_id,
                        'friends': friends
                    })
                else:
                    messages.error(request, 'Ошибка при получении данных пользователя.')
                    return render(request, 'user_profile.html', {'error': 'Ошибка при получении данных пользователя'}, status=response.status_code)
            except httpx.RequestError as exc:
                return render(request, 'user_profile.html', {'error': 'Ошибка запроса'}, status=500)
            except Exception as e:
                return render(request, 'user_profile.html', {'error': 'Неожиданная ошибка'}, status=500)
    else:
        return render(request, 'user_profile.html', {'error': 'ID пользователя не предоставлен'}, status=400)

async def update_user(request):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_name = await sync_to_async(request.session.get)('user_name')
    user_pass = await sync_to_async(request.session.get)('password')

    if request.method == 'POST':
        form = UpdateUserForm(request.POST)
        if form.is_valid():
            new_email = form.cleaned_data['newEmail'] if form.cleaned_data['newEmail'] else user_email
            new_name = form.cleaned_data['newName'] if form.cleaned_data['newName'] else user_name
            new_password = form.cleaned_data['newPassword'] if form.cleaned_data.get('newPassword') else user_pass

            user_data = {
                'email': user_email,
                'password': user_pass,
                'newEmail': new_email,
                'newName': new_name,
                'newPassword': new_password,
            }
            encoded_data = base64.b64encode(json.dumps(user_data).encode()).decode()

            print(user_data)
            print(encoded_data)

            url = 'http://localhost:8081/api/users'
            print("Отправка запроса на URL:", url)
            print("Отправляемые данные:", user_data)
            print("Заголовок Authorization:", encoded_data)

            async with httpx.AsyncClient() as client:
                try:
                    headers = {'Authorization': encoded_data}
                    response = await client.put(url, headers=headers, json=user_data)
                    print("Запрос отправлен. Статус ответа:", response.status_code)
                    print("Ответ сервера:", response.text)

                    if response.status_code == 200:
                        user_info = response.json()
                        await sync_to_async(request.session.__setitem__)('user_name', user_info['name'])
                        await sync_to_async(request.session.__setitem__)('user_email', user_info['email'])
                        await sync_to_async(request.session.__setitem__)('password', user_info['new_password'])

                        messages.success(request, 'Пользователь успешно обновлен!')
                        print("Пользователь обновлен: {}.".format(user_info['name']))

                        return HttpResponseRedirect(f'/user_profile/{user_info["id"]}')
                    else:
                        messages.error(request, 'Ошибка обновления пользователя: ' + response.text)
                        print("Ошибка обновления пользователя: Статус ответа {}.".format(response.status_code))
                except httpx.RequestError as exc:
                    print(f"Ошибка запроса: {exc}")
                except Exception as e:
                    print(f"Неожиданная ошибка: {str(e)}")
    else:
        form = UpdateUserForm(initial={'newEmail': user_email, 'newName': user_name})

    return render(request, 'update_user.html', {'form': form})

async def logout_view(request):
    print(f"user_id: {await sync_to_async(request.session.get)('user_id')}")
    print(f"user_name: {await sync_to_async(request.session.get)('user_name')}")
    print(f"user_email: {await sync_to_async(request.session.get)('user_email')}")
    print(f"user_pass: {await sync_to_async(request.session.get)('password')}")

    await sync_to_async(request.session.flush)()
    await sync_to_async(logout)(request)

    messages.success(request, 'Вы успешно вышли из системы.')
    return HttpResponseRedirect('/')
async def get_all_users(request):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        messages.error(request, 'Вы не авторизованы. Пожалуйста, войдите в систему.')
        return redirect('login')

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = 'http://localhost:8081/api/users'
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers={'Authorization': token})
            if response.status_code == 200:
                users = response.json()
                print("Список пользователей:", users)
                return users
            else:
                messages.error(request, 'Ошибка при получении списка пользователей.')
                return []
        except httpx.RequestError as exc:
            print(f"Ошибка запроса: {exc}")
            return []
        except Exception as e:
            print(f"Неожиданная ошибка: {str(e)}")
            return []

async def friends_and_users_view(request):
    users = await get_all_users(request)
    search = request.GET.get('search', '')
    friends = [
        {'name': 'friend1'},
        {'name': 'friend2'}
    ]

    return await sync_to_async(render)(request, 'friends_and_users.html', {
        'search': search,
        'friends': friends,
        'users': users
    })


async def get_users_by_name(request, namePrefix):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        messages.error(request, 'Вы не авторизованы. Пожалуйста, войдите в систему.')
        return redirect('login')

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = f'http://localhost:8081/api/users/name/{namePrefix}'
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers={'Authorization': token})
            if response.status_code == 200:
                users = response.json()
                print("Список пользователей:", users)
                return JsonResponse(users, safe=False)
            else:
                messages.error(request, 'Ошибка при получении списка пользователей.')
                return JsonResponse({'error': 'Ошибка при получении списка пользователей'}, status=response.status_code)
        except httpx.RequestError as exc:
            print(f"Ошибка запроса: {exc}")
            return JsonResponse({'error': 'Ошибка запроса'}, status=500)
        except Exception as e:
            print(f"Неожиданная ошибка: {str(e)}")
            return JsonResponse({'error': 'Неожиданная ошибка'}, status=500)


async def get_user_games(request):
    user_id = await sync_to_async(request.session.get)('user_id')
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        messages.error(request, 'Вы не авторизованы. Пожалуйста, войдите в систему.')
        return redirect('login')

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = 'http://localhost:8081/api/users/games/history'
    async with httpx.AsyncClient() as client:
        try:
            print("Отправка запроса на URL:", url)
            print("Заголовок Authorization:", token)
            response = await client.get(url, headers={'Authorization': token})
            print("Запрос отправлен. Статус ответа:", response.status_code)
            print("Ответ сервера:", response.text)



            if response.status_code == 200:

                games = response.json()

                for game in games:
                    iso_date = game['data']
                    # Удаление дробной части времени
                    iso_date = iso_date.split('.')[0]
                    datetime_obj = datetime.datetime.strptime(iso_date, '%Y-%m-%dT%H:%M:%S')
                    formatted_date = format(datetime_obj,
                                            'H:i d F Y')  # Форматирование даты как "час:минута день месяц год"
                    game['formatted_date'] = formatted_date  # Добавляем отформатированную дату в словарь игры

                print("Список игр:", games)
                return await sync_to_async(render)(request, 'user_games.html', {'games': games, 'id':user_id})

                # print("Список игр:", games)
                # return await sync_to_async(render)(request, 'user_games.html', {'games': games})
            else:
                error_message = f'Ошибка при получении списка игр. Статус ответа: {response.status_code}, Ответ: {response.text}'
                print(error_message)
                messages.error(request, error_message)
                return await sync_to_async(render)(request, 'user_games.html', {'games': []})
        except httpx.RequestError as exc:
            error_message = f"Ошибка запроса: {exc}"
            print(error_message)
            return await sync_to_async(render)(request, 'user_games.html', {'games': []})
        except Exception as e:
            error_message = f"Неожиданная ошибка: {str(e)}"
            print(error_message)
            return await sync_to_async(render)(request, 'user_games.html', {'games': []})


async def add_friend(request, id):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        messages.error(request, 'Вы не авторизованы. Пожалуйста, войдите в систему.')
        return redirect('login')

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = f'http://localhost:8081/api/users/friends/{id}'
    async with httpx.AsyncClient() as client:
        try:
            print("Отправка запроса на URL:", url)
            print("Заголовок Authorization:", token)
            response = await client.post(url, headers={'Authorization': token})
            print("Запрос отправлен. Статус ответа:", response.status_code)
            print("Ответ сервера:", response.text)

            if response.status_code == 200:
                    print("Друг успешно добавлен")
                    return redirect('friends_and_users')
            else:
                error_message = f'Ошибка при добавлении друга. Статус ответа: {response.status_code}, Ответ: {response.text}'
                print(error_message)
                messages.error(request, error_message)
                return JsonResponse({'error': error_message}, status=response.status_code)
        except httpx.RequestError as exc:
            error_message = f"Ошибка запроса: {exc}"
            print(error_message)
            return JsonResponse({'error': error_message}, status=500)
        except Exception as e:
            error_message = f"Неожиданная ошибка: {str(e)}"
            print(error_message)
            return JsonResponse({'error': error_message}, status=500)


async def get_all_friends(request):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        messages.error(request, 'Вы не авторизованы. Пожалуйста, войдите в систему.')
        return redirect('login')

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = 'http://localhost:8081/api/users/friends/all-friends'
    async with httpx.AsyncClient() as client:
        try:
            print("Отправка запроса на URL:", url)
            print("Заголовок Authorization:", token)
            response = await client.get(url, headers={'Authorization': token})
            print("Запрос отправлен. Статус ответа:", response.status_code)
            print("Ответ сервера:", response.text)

            if response.status_code == 200:
                try:
                    friends_list = response.json()
                    print("Список друзей:", friends_list)
                    return JsonResponse(friends_list, safe=False)
                except json.JSONDecodeError:
                    error_message = f"Ошибка декодирования JSON: Ответ сервера не является допустимым JSON. Ответ: {response.text}"
                    print(error_message)
                    return JsonResponse({'error': error_message}, status=500)
            else:
                error_message = f'Ошибка при получении списка друзей. Статус ответа: {response.status_code}, Ответ: {response.text}'
                print(error_message)
                messages.error(request, error_message)
                return JsonResponse({'error': error_message}, status=response.status_code)
        except httpx.RequestError as exc:
            error_message = f"Ошибка запроса: {exc}"
            print(error_message)
            return JsonResponse({'error': error_message}, status=500)
        except Exception as e:
            error_message = f"Неожиданная ошибка: {str(e)}"
            print(error_message)
            return JsonResponse({'error': error_message}, status=500)


async def get_several_friends(request, count):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        messages.error(request, 'Вы не авторизованы. Пожалуйста, войдите в систему.')
        return redirect('login')

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = f'http://localhost:8081/api/users/friends/several-friends/{count}'
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers={'Authorization': token})
            if response.status_code == 200:
                try:
                    friends_list = response.json()
                    return friends_list
                except json.JSONDecodeError:
                    error_message = f"Ошибка декодирования JSON: Ответ сервера не является допустимым JSON. Ответ: {response.text}"
                    messages.error(request, error_message)
                    return []
            else:
                error_message = f'Ошибка при получении списка друзей. Статус ответа: {response.status_code}, Ответ: {response.text}'
                messages.error(request, error_message)
                return []
        except httpx.RequestError as exc:
            error_message = f"Ошибка запроса: {exc}"
            messages.error(request, error_message)
            return []
        except Exception as e:
            error_message = f"Неожиданная ошибка: {str(e)}"
            messages.error(request, error_message)
            return []

async def delete_friend(request, id):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        messages.error(request, 'Вы не авторизованы. Пожалуйста, войдите в систему.')
        return redirect('login')

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = f'http://localhost:8081/api/users/friends/{id}'
    async with httpx.AsyncClient() as client:
        try:
            print("Отправка запроса на URL:", url)
            print("Заголовок Authorization:", token)
            response = await client.delete(url, headers={'Authorization': token})
            print("Запрос отправлен. Статус ответа:", response.status_code)
            print("Ответ сервера:", response.text)

            if response.status_code == 200:
                try:
                    result = response.json()
                    print("Друг удален:", result)
                    messages.success(request, 'Друг успешно удален.')
                    return redirect('friends_and_users')
                except json.JSONDecodeError:
                    error_message = f"Ошибка декодирования JSON: Ответ сервера не является допустимым JSON. Ответ: {response.text}"
                    print(error_message)
                    messages.error(request, error_message)
                    return redirect('friends_and_users')
            else:
                error_message = f'Ошибка при удалении друга. Статус ответа: {response.status_code}, Ответ: {response.text}'
                print(error_message)
                messages.error(request, error_message)
                return redirect('friends_and_users')
        except httpx.RequestError as exc:
            error_message = f"Ошибка запроса: {exc}"
            print(error_message)
            messages.error(request, error_message)
            return redirect('friends_and_users')
        except Exception as e:
            error_message = f"Неожиданная ошибка: {str(e)}"
            print(error_message)
            messages.error(request, error_message)
            return redirect('friends_and_users')

async def search_friends_by_nick(request, nick):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        messages.error(request, 'Вы не авторизованы. Пожалуйста, войдите в систему.')
        return redirect('login')

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = f'http://localhost:8081/api/users/friends/{nick}'
    async with httpx.AsyncClient() as client:
        try:
            print("Отправка запроса на URL:", url)
            print("Заголовок Authorization:", token)
            response = await client.get(url, headers={'Authorization': token})
            print("Запрос отправлен. Статус ответа:", response.status_code)
            print("Ответ сервера:", response.text)

            if response.status_code == 200:
                try:
                    friends_list = response.json()
                    print("Список друзей:", friends_list)
                    return JsonResponse(friends_list, safe=False)
                except json.JSONDecodeError:
                    error_message = f"Ошибка декодирования JSON: Ответ сервера не является допустимым JSON. Ответ: {response.text}"
                    print(error_message)
                    return JsonResponse({'error': error_message}, status=500)
            else:
                error_message = f'Ошибка при поиске друзей. Статус ответа: {response.status_code}, Ответ: {response.text}'
                print(error_message)
                messages.error(request, error_message)
                return JsonResponse({'error': error_message}, status=response.status_code)
        except httpx.RequestError as exc:
            error_message = f"Ошибка запроса: {exc}"
            print(error_message)
            return JsonResponse({'error': error_message}, status=500)
        except Exception as e:
            error_message = f"Неожиданная ошибка: {str(e)}"
            print(error_message)
            return JsonResponse({'error': error_message}, status=500)
async def friends_and_users_view(request):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        messages.error(request, 'Вы не авторизованы. Пожалуйста, войдите в систему.')
        return redirect('login')

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    search = request.GET.get('search', '')

    async with httpx.AsyncClient() as client:
        if search:

            friends_url = f'http://localhost:8081/api/users/friends/{search}'
            users_url = f'http://localhost:8081/api/users/name/{search}'
            try:
                friends_response = await client.get(friends_url, headers={'Authorization': token})
                users_response = await client.get(users_url, headers={'Authorization': token})

                if friends_response.status_code == 200:
                    try:
                        friends = friends_response.json()
                    except json.JSONDecodeError:
                        friends = []
                        print("Ошибка декодирования JSON для списка друзей.")
                else:
                    friends = []
                    print(f"Ошибка при получении списка друзей: {friends_response.status_code}")

                if users_response.status_code == 200:
                    try:
                        users = users_response.json()
                    except json.JSONDecodeError:
                        users = []
                        print("Ошибка декодирования JSON для списка пользователей.")
                else:
                    users = []
                    print(f"Ошибка при получении списка пользователей: {users_response.status_code}")

                return await sync_to_async(render)(request, 'friends_and_users.html', {'friends': friends, 'users': users, 'search': search})

            except httpx.RequestError as exc:
                print(f"Ошибка запроса: {exc}")
                return await sync_to_async(render)(request, 'friends_and_users.html', {'friends': [], 'users': [], 'search': search})
            except Exception as e:
                print(f"Неожиданная ошибка: {str(e)}")
                return await sync_to_async(render)(request, 'friends_and_users.html', {'friends': [], 'users': [], 'search': search})
        else:
            friends_url = 'http://localhost:8081/api/users/friends/all-friends'
            users_url = 'http://localhost:8081/api/users'
            try:
                friends_response = await client.get(friends_url, headers={'Authorization': token})
                users_response = await client.get(users_url, headers={'Authorization': token})

                if friends_response.status_code == 200:
                    try:
                        friends = friends_response.json()
                    except json.JSONDecodeError:
                        friends = []
                        print("Ошибка декодирования JSON для списка друзей.")
                else:
                    friends = []
                    print(f"Ошибка при получении списка друзей: {friends_response.status_code}")

                if users_response.status_code == 200:
                    try:
                        users = users_response.json()
                    except json.JSONDecodeError:
                        users = []
                        print("Ошибка декодирования JSON для списка пользователей.")
                else:
                    users = []
                    print(f"Ошибка при получении списка пользователей: {users_response.status_code}")

                return await sync_to_async(render)(request, 'friends_and_users.html', {'friends': friends, 'users': users, 'search': search})

            except httpx.RequestError as exc:
                print(f"Ошибка запроса: {exc}")
                return await sync_to_async(render)(request, 'friends_and_users.html', {'friends': [], 'users': [], 'search': search})
            except Exception as e:
                print(f"Неожиданная ошибка: {str(e)}")
                return await sync_to_async(render)(request, 'friends_and_users.html', {'friends': [], 'users': [], 'search': search})


def index(request):
    return render(request, 'index.html')

def rules(request):
    return render(request, 'rules.html')


async def merge_videos(request):
    try:
        user_email = await sync_to_async(request.session.get)('user_email')
        user_pass = await sync_to_async(request.session.get)('password')
        if not user_email:
            return JsonResponse({'error': 'Вы не авторизованы'}, status=401)

        user_data = {
            'email': user_email,
            'password': user_pass,
        }
        token = base64.b64encode(json.dumps(user_data).encode()).decode()

        url = 'http://localhost:8081/api/video/mergeVideos'
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url, headers={'Authorization': token}, timeout=15000)

                if response.status_code == 200:
                    video_content = response.content
                    base64_video = base64.b64encode(video_content).decode('utf-8')
                    return JsonResponse({'video': base64_video})
                else:
                    error_message = f'Ошибка при получении видео: {response.status_code}. Ответ: {response.text}'
                    return JsonResponse({'error': error_message}, status=response.status_code)
            except httpx.RequestError as exc:
                error_message = f'Ошибка запроса: {exc}'
                return JsonResponse({'error': error_message}, status=500)
            except Exception as e:
                error_message = f'Неожиданная ошибка: {str(e)}'
                return JsonResponse({'error': error_message}, status=500)
    except Exception as e:
        error_message = f'Неожиданная ошибка на уровне сессии: {str(e)}'
        return JsonResponse({'error': error_message}, status=500)
async def send_game_results(request, win_id, lose_id):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        return JsonResponse({'error': 'Вы не авторизованы'}, status=401)

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = f'http://localhost:8081/api/users/games/{win_id}/{lose_id}'
    print(url)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, headers={'Authorization': token})
            if response.status_code == 200:
                return JsonResponse({'message': 'Результаты записаны'}, status=200)
            else:
                return JsonResponse({'error': 'Ошибка при записи результатов'}, status=response.status_code)
        except httpx.RequestError as exc:
            return JsonResponse({'error': f'Error: {exc}'}, status=500)

def play_game(request):

    print(f"user_id: {(request.session.get)('user_id')}")
    user_id = (request.session.get)('user_id')
    USER_IDS.append(user_id)
    print(USER_IDS)
    return render(request, 'play_game.html', {'room_name': 'test_room', 'user_id': user_id})

async def get_user_games_info(request):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        return JsonResponse({'error': 'Вы не авторизованы'}, status=401)

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = 'http://localhost:8081/api/users/games/info'
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers={'Authorization': token})
            if response.status_code == 200:
                game_info = response.json()
                print(game_info)
                return JsonResponse(game_info, safe=False)
            else:
                return JsonResponse({'error': f'Ошибка при получении информации о играх: {response.status_code}'}, status=response.status_code)
        except httpx.RequestError as exc:
            return JsonResponse({'error': f'Ошибка запроса: {exc}'}, status=500)
        except Exception as e:
            return JsonResponse({'error': f'Неожиданная ошибка: {str(e)}'}, status=500)

async def get_user_games_info_by_id(request, id):
    user_email = await sync_to_async(request.session.get)('user_email')
    user_pass = await sync_to_async(request.session.get)('password')
    if not user_email:
        return JsonResponse({'error': 'Вы не авторизованы'}, status=401)

    user_data = {
        'email': user_email,
        'password': user_pass,
    }
    token = base64.b64encode(json.dumps(user_data).encode()).decode()

    url = f'http://localhost:8081/api/users/games/info/{id}'
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers={'Authorization': token})
            if response.status_code == 200:
                game_info = response.json()
                return JsonResponse(game_info, safe=False)
            else:
                return JsonResponse({'error': f'Ошибка при получении информации о играх: {response.status_code}'}, status=response.status_code)
        except httpx.RequestError as exc:
            return JsonResponse({'error': f'Ошибка запроса: {exc}'}, status=500)
        except Exception as e:
            return JsonResponse({'error': f'Неожиданная ошибка: {str(e)}'}, status=500)