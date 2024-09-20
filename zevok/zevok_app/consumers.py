import json
from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
import cv2
import numpy as np
from .nn_handler import predict
import base64

class VideoConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'room_{self.room_name}'
        self.user_id = None

        self.opponent_id = None
        self.game_over = False

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        print(self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        global USER_IDS

        data = json.loads(text_data)
        message_type = data.get('type')
        user_id = data.get('user_id')

        if not self.user_id:
            self.user_id = user_id


        for i in USER_IDS:
            if self.user_id != int(i):
                self.opponent_id = i
        print(f'opponent {self.opponent_id}, {user_id}')
        print(f'IDS {USER_IDS}, self id{self.user_id}, opponent {self.opponent_id}')

        print(f"Message type: {message_type}, User ID: {user_id}")

        if message_type in ['offer', 'answer', 'candidate', 'ready', 'frame'] and not self.game_over:
            if message_type == "ready":
                await self.channel_layer.send(
                    self.channel_name,
                    {
                        'type': 'video_message',
                        'message': data
                    }
                )
                data['type'] = ""

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'video_message',
                    'message': data
                }
            )
            if message_type == 'frame':
                print("Processing frame")
                frame = self.decode_frame(data['frame'])

                if frame is not None:
                    yawning = await sync_to_async(self.handle_video_frame)(frame)
                    if yawning:
                        self.game_over = True
                        loser_id = self.user_id
                        winner_id = self.opponent_id
                        print(f'Победитель: {winner_id}, Проигравший: {loser_id}')
                        await self.send_game_results(winner_id, loser_id)
                        await self.channel_layer.group_send(
                            self.room_group_name,
                            {
                                'type': 'video_message',
                                'message': {
                                    'type': 'emotion',
                                    'user_id': self.user_id,
                                    'opponent_id': self.opponent_id,
                                    'yawning': yawning,
                                    'winner_id': winner_id,
                                    'loser_id': loser_id
                                }
                            }
                        )
                        USER_IDS = []

    async def video_message(self, event):
        message = event['message']
        await self.send(text_data=json.dumps(message))

    def decode_frame(self, frame_data):
        nparr = np.frombuffer(base64.b64decode(frame_data), np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        return frame

    def encode_frame(self, frame):
        _, buffer = cv2.imencode('.jpg', frame)
        return base64.b64encode(buffer).decode('utf-8')

    def handle_video_frame(self, frame):
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        face_cascade = cv2.CascadeClassifier('/Users/pavelbandurovskij/PycharmProjects/dip/haarcascade_frontalface_alt.xml')
        faces = face_cascade.detectMultiScale(gray, 1.3, 5)
        for (x, y, w, h) in faces:
            roi = gray[y:y + h, x:x + w]
            if roi is not None:
                resized_img = cv2.resize(roi, (48, 48))
                resized_img = resized_img.reshape(1, 48, 48, 1)
                resized_img = resized_img.astype('float32') / 255

                emotion = predict(resized_img)
                print(f"Эмоция {emotion}")
                if emotion == "yawning":
                    return True
        return False
