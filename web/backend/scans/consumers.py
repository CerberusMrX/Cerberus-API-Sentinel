import json
from channels.generic.websocket import AsyncWebsocketConsumer

class ScanConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.room_group_name = f'scan_{self.scan_id}'

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()
        
        # Send connection confirmation
        await self.send(text_data=json.dumps({
            'type': 'connection_established',
            'log': 'WebSocket connection established.',
            'progress': 0
        }))

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    async def receive(self, text_data):
        # We don't expect to receive messages from the client for now,
        # but we can handle them if needed.
        pass

    # Receive message from room group
    async def scan_update(self, event):
        # Send message to WebSocket
        await self.send(text_data=json.dumps(event['data']))
