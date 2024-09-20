"""
ASGI config for zevok project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os

from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
import sys
sys.path.append("zevok")
import zevok_app.routing as rout

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zevok.settings')

application = ProtocolTypeRouter({
   "http": get_asgi_application(),
   "websocket": URLRouter(
       rout.websocket_urlpatterns
    # re_path(r'room/yawn/', consumers.VideoConsumer.as_asgi()),
   ),
})