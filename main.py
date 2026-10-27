import os
import logging
from datetime import timedelta
from typing import Any
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import Integer, String, ForeignKey
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

# --------------------------------------------------
# Flask configuration
# --------------------------------------------------

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Configure SECRET_KEY in Render and in your local environment.
# Do not generate a new key every time the app starts.
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required.")

app.config["SECRET_KEY"] = secret_key

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "sqlite:///users.db",
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
}
socketio = SocketIO(app, cors_allowed_origins="*",async_mode="gevent")
socket_users: dict[str, int] = {}


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
db.init_app(app)


@app.after_request
def log_request(response: Response) -> Response:
    app.logger.info(
        "HTTP %s %s -> %s",
        request.method,
        request.path,
        response.status_code,
    )
    return response


# --------------------------------------------------
# Database models
# --------------------------------------------------

class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )
    name: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    email: Mapped[str] = mapped_column(
        String(254), unique=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(
        String(300), nullable=False
    )

    messages: Mapped[list["Message"]] = db.relationship(
        "Message",
        back_populates="author",
    )


class Message(db.Model):
    __tablename__ = "message"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    # Foreign-key column
    author_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )

    message: Mapped[str] = mapped_column(
        "message",
        String(500),
        nullable=False,
    )

    # Relationship to the User object
    author: Mapped["User"] = db.relationship(
        "User",
        back_populates="messages",
    )


# --------------------------------------------------
# Token helpers
# --------------------------------------------------
TOKEN_MAX_AGE = int(timedelta(days=1).total_seconds())


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt="flutter-auth",
    )


def _create_token(user: User) -> str:
    return _serializer().dumps({
        "user_id": user.id,
    })


def _user_json(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
    }


def _user_from_token(token: object) -> User | None:
    if not isinstance(token, str) or not token:
        return None

    try:
        payload = _serializer().loads(
            token,
            max_age=TOKEN_MAX_AGE,
        )
    except BadSignature:
        return None

    if not isinstance(payload, dict):
        return None

    user_id = payload.get("user_id")
    if type(user_id) is not int or user_id <= 0:
        return None

    return db.session.get(User, user_id)


def _authorized_user() -> User | None:
    """
    Read and verify the Bearer token.
    Return the authenticated user or None.
    """
    authorization = request.headers.get("Authorization", "")
    parts = authorization.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    return _user_from_token(parts[1])


def _json_body() -> dict[str, Any] | None:
    body = request.get_json(silent=True)

    if isinstance(body, dict):
        return body

    return None


# --------------------------------------------------
# Health check
# --------------------------------------------------

@app.get("/")
def health_check() -> Response:
    return jsonify(status="ok", service="chat-app-server")


# --------------------------------------------------
# Register
# --------------------------------------------------

@app.post("/api/register")
def register() -> tuple[Response, int]:
    body = _json_body()

    if body is None:
        return jsonify(
            error="Request body must be a JSON object."
        ), 400

    name = body.get("name")
    email = body.get("email")
    password = body.get("password")

    if not all(
        isinstance(value, str)
        for value in (name, email, password)
    ):
        return jsonify(
            error="name, email, and password are required."
        ), 400

    name = name.strip()
    email = email.strip().lower()

    if not name or len(name) > 50:
        return jsonify(
            error="name must be between 1 and 50 characters."
        ), 400

    local_part, separator, domain = email.partition("@")

    if (
        len(email) > 254
        or not separator
        or not local_part
        or not domain
        or "." not in domain
    ):
        return jsonify(
            error="A valid email address is required."
        ), 400

    if len(password) < 8:
        return jsonify(
            error="password must be at least 8 characters."
        ), 400

    user = User(
        name=name,
        email=email,
        password_hash=generate_password_hash(password),
    )

    db.session.add(user)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify(
            error="An account with this email already exists."
        ), 409

    return jsonify(
        user=_user_json(user),
        token=_create_token(user),
    ), 201


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.post("/api/login")
def login() -> tuple[Response, int]:
    body = _json_body()

    if body is None:
        return jsonify(
            error="Request body must be a JSON object."
        ), 400

    email = body.get("email")
    password = body.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify(
            error="email and password are required."
        ), 400

    user = db.session.query(User).filter_by(
        email=email.strip().lower()
    ).first()

    if user is None or not check_password_hash(
        user.password_hash, password
    ):
        return jsonify(
            error="Invalid email or password."
        ), 401

    return jsonify(
        user=_user_json(user),
        token=_create_token(user),
    ), 200


# --------------------------------------------------
# Send message: authentication required
# --------------------------------------------------
def _message_json(message: Message) -> dict[str, Any]:
    return {
        "id": message.id,
        "author": message.author.name,
        "author_id": message.author.id,
        "message": message.message,
    }


@app.post("/api/send-message")
def send_message() -> tuple[Response, int]:
    # 1. Authenticate the user before saving anything.
    user = _authorized_user()

    if user is None:
        return jsonify(
            error="A valid bearer token is required."
        ), 401

    # 2. Validate the JSON request body.
    body = _json_body()

    if body is None:
        return jsonify(
            error="Request body must be a JSON object."
        ), 400

    message_content = body.get("message")

    if not isinstance(message_content, str):
        return jsonify(
            error="message is required."
        ), 400

    message_content = message_content.strip()

    if not message_content or len(message_content) > 500:
        return jsonify(
            error="message must be between 1 and 500 characters."
        ), 400

    # 3. Use the authenticated user, never a client-supplied ID.
    message = Message(
        author_id=user.id,
        message=message_content,
    )

    try:
        db.session.add(message)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Could not save message.")
        return jsonify(
            error="Could not save message."
        ), 500

    # 4. Return the saved message.
    return jsonify(
        message=_message_json(message)
    ), 201


@app.get("/api/messages")
def get_messages() -> Response | tuple[Response, int]:
    if _authorized_user() is None:
        return jsonify(
            error="A valid bearer token is required."
        ), 401
    messages = (
        db.session.query(Message)
        .order_by(Message.id.asc())
        .all()
    )
    return jsonify(messages=[_message_json(message) for message in messages])

# --------------------------------------------------
# Current authenticated user
# --------------------------------------------------


@app.get("/api/me")
def me() -> Response | tuple[Response, int]:
    user = _authorized_user()

    if user is None:
        return jsonify(
            error="A valid bearer token is required."
        ), 401

    return jsonify(user=_user_json(user))


@socketio.on('connect')
def handle_connect(auth: Any = None) -> bool | None:
    token = auth.get("token") if isinstance(auth, dict) else None
    if token is None:
        authorization = request.headers.get("Authorization", "")
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]

    user = _user_from_token(token)
    if user is None:
        app.logger.warning("Rejected unauthenticated Socket.IO connection.")
        return False

    socket_users[request.sid] = user.id
    app.logger.info(
        "Socket.IO connected: user_id=%s sid=%s",
        user.id,
        request.sid,
    )
    emit("server_response", {"message": "You are connected!"})


@socketio.on('disconnect')
def handle_disconnect() -> None:
    user_id = socket_users.pop(request.sid, None)
    if user_id is not None:
        app.logger.info(
            "Socket.IO disconnected: user_id=%s sid=%s",
            user_id,
            request.sid,
        )


@socketio.on('send_message')
def handle_send_message(data: Any) -> None:
    user_id = socket_users.get(request.sid)
    user = db.session.get(User, user_id) if user_id is not None else None
    if user is None:
        emit("error", {"message": "A valid bearer token is required."})
        return

    if not isinstance(data, dict):
        emit("error", {"message": "Message must be a JSON object."})
        return

    message_content = data.get("message")
    if not isinstance(message_content, str) or not message_content.strip():
        emit("error", {"message": "Message must be a non-empty string."})
        return

    message_content = message_content.strip()

    if len(message_content) > 500:
        emit(
            "error", {"message": "Message must be between 1 and 500 characters."})
        return

    message = Message(
        author_id=user.id,
        message=message_content,
    )

    try:
        db.session.add(message)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Could not save message.")
        emit("error", {"message": "Could not save message."})
        return

    app.logger.info(
        "Socket.IO message saved: user_id=%s message_id=%s",
        user.id,
        message.id,
    )
    emit("new_message", _message_json(message), broadcast=True)


if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
    )
