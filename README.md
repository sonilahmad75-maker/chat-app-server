# chat-app-server

## Run locally

Install the dependencies from `requirements.txt`, set `SECRET_KEY` to a
persistent random value, then start the server with `python main.py`. The app
listens on port `5000` by default; set `PORT` to override it. `DATABASE_URL`
is optional and defaults to a local SQLite database.

## Socket.IO

Authenticate the Socket.IO connection by passing the API bearer token as
`auth: { "token": "<token>" }`. Send messages with the `send_message` event
and a payload shaped like `{ "message": "Hello" }`. Successful messages are
saved before the server broadcasts them with the `new_message` event.