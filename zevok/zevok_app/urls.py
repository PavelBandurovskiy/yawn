from . import views
from django.urls import path

from .views import merge_videos

urlpatterns = [
    path('', views.index, name='index'),

    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('user_profile/<int:id>/', views.get_user_info, name='user_profile'),
    path('update_user/', views.update_user, name='update_user'),
    path('api/get_all_users/', views.get_all_users, name='get_all_users'),
    path('api/name/<str:namePrefix>/', views.get_users_by_name, name='get_users_by_name'),
    path('api/users/games/', views.get_user_games, name='get_user_games'),
    path('api/users/friends/<int:id>/', views.add_friend, name='add_friend'),
    path('api/users/friends/all-friends/', views.get_all_friends, name='get_all_friends'),
    path('api/users/friends/several-friends/<int:count>/', views.get_several_friends, name='get_several_friends'),
    path('api/users/friends/delete-friend/<int:id>/', views.delete_friend, name='delete_friend'),
    path('api/users/friends/find/<str:nick>/', views.search_friends_by_nick, name='search_friends_by_nick'),
    path('friends/', views.friends_and_users_view, name='friends_and_users'),
    path('games/', views.get_user_games, name='user_games'),
    path('logout/', views.logout_view, name='logout'),
    path('rules/', views.rules, name='rules'),
    path('play/', views.play_game, name='play_game'),
    path('results/<int:win_id>/<int:lose_id>', views.send_game_results, name="results"),
    path('api/users/games/info/', views.get_user_games_info, name='get_user_games_info'),
    path('api/users/games/info/<int:id>/', views.get_user_games_info_by_id, name='get_user_games_info_by_id'),
    path('api/video/mergeVideos/', merge_videos, name='merge_videos'),
]