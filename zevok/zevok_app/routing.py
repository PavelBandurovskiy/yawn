
from django.urls import path, re_path
from . import consumers

websocket_urlpatterns = [

    re_path(r'ws/room/(?P<room_name>\w+)/$', consumers.VideoConsumer.as_asgi()),
    ]