# chat-app-server

## Run locally

Install the dependencies from `requirements.txt`, set `SECRET_KEY` to a
persistent random value, then initialize the database with
`flask --app main init-db`. This creates any missing tables; it does not migrate
existing tables. Start the server with `python main.py`. The app listens on
port `5000` by default; set `PORT` to override it. `DATABASE_URL` is optional
and defaults to a local SQLite database.

## Socket.IO

Authenticate the Socket.IO connection by passing the API bearer token as
`auth: { "token": "<token>" }`. Send messages with the `send_message` event
and a payload shaped like `{ "room_id": 1, "message": "Hello" }`. Join the
room with the `join_room` event and `{ "room_id": 1 }` to receive messages.
Successful messages are saved before the server broadcasts them with the
`new_message` event.

## API smoke test

Set `CHAT_API_TOKEN` to a current bearer token, optionally set `CHAT_API_URL`,
then run `python test.py`. The script does not contain credentials.