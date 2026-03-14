import asyncio
import websockets
import json


async def test_realtime_ws():
    uri = "ws://localhost:8000/api/v1/realtime/ws"
    print(f"Connecting to {uri}...")
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected! Waiting for messages...")
            while True:
                message = await websocket.recv()
                data = json.loads(message)
                print(f"Received {data['type']} at {data['timestamp']}")
                if data["type"] == "LIVE_METRICS":
                    print(
                        f"Metrics: Events={data['payload']['totalEvents']}, CPU={data['payload']['system_health']['cpu']}%"
                    )
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(test_realtime_ws())
