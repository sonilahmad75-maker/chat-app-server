import os
import logging
from datetime import timedelta
from typing import Any
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import UniqueConstraint
from sqlalchemy import Integer, String, ForeignKey
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import text
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
    "sqlite:///users.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
}
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")
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


# ====--------------------------------------------------
# ##              Database models
# ====--------------------------------------------------

# =========================
# Users Table
# =========================
class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    name: Mapped[str] = mapped_column(
        db.String(100),
        nullable=False
    )

    email: Mapped[str] = mapped_column(
        db.String(255),
        nullable=False,
        unique=True
    )

    password_hash: Mapped[str] = mapped_column(
        db.String(255),
        nullable=False
    )

    # Relationships
    contacts: Mapped[list["Contact"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan"
    )

    messages: Mapped[list["Message"]] = relationship(
        back_populates="author",
        cascade="all, delete-orphan"
    )

    room_memberships: Mapped[list["UserRoom"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan"
    )


# =========================
# Contacts Table
# =========================
class Contact(db.Model):
    __tablename__ = "contacts"

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    name: Mapped[str] = mapped_column(
        db.String(100),
        nullable=False
    )

    email: Mapped[str] = mapped_column(
        db.String(255),
        nullable=False
    )

    # Foreign key -> users.id
    user_id: Mapped[int] = mapped_column(
        db.ForeignKey("users.id"),
        nullable=False
    )

    # Relationship
    user: Mapped["User"] = relationship(
        back_populates="contacts"
    )


# =========================
# Rooms Table
# =========================
class Room(db.Model):
    __tablename__ = "rooms"

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    name: Mapped[str] = mapped_column(
        db.String(100),
        nullable=False
    )

    # Relationships
    messages: Mapped[list["Message"]] = relationship(
        back_populates="room",
        cascade="all, delete-orphan"
    )

    user_memberships: Mapped[list["UserRoom"]] = relationship(
        back_populates="room",
        cascade="all, delete-orphan"
    )


# =========================
# Messages Table
# =========================
class Message(db.Model):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    # Foreign key -> users.id
    author_id: Mapped[int] = mapped_column(
        db.ForeignKey("users.id"),
        nullable=False
    )

    # Foreign key -> rooms.id
    room_id: Mapped[int] = mapped_column(
        db.ForeignKey("rooms.id"),
        nullable=False
    )

    message: Mapped[str] = mapped_column(
        db.String(500),
        nullable=False
    )

    # Relationships
    author: Mapped["User"] = relationship(
        back_populates="messages"
    )

    room: Mapped["Room"] = relationship(
        back_populates="messages"
    )


# =========================
# User_Room Table
# =========================
class UserRoom(db.Model):
    __tablename__ = "user_room"

    # Optional constraint to prevent duplicate membership
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "room_id",
            name="uq_user_room"
        ),
    )

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    # Foreign key -> users.id
    user_id: Mapped[int] = mapped_column(
        db.ForeignKey("users.id"),
        nullable=False
    )

    # Foreign key -> rooms.id
    room_id: Mapped[int] = mapped_column(
        db.ForeignKey("rooms.id"),
        nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship(
        back_populates="room_memberships"
    )

    room: Mapped["Room"] = relationship(
        back_populates="user_memberships"
    )


# --------------------------------------------------
# Token helpers
# --------------------------------------------------
TOKEN_MAX_AGE = int(timedelta(days=1).total_seconds())
with app.app_context():
    db.create_all()


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


def is_room_member(user_id: int, room_id: int) -> bool:
    membership = db.session.query(UserRoom).filter_by(
        user_id=user_id,
        room_id=room_id,
    ).first()

    return membership is not None

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
        "room_id": message.room_id,
        "author": message.author.name,
        "author_id": message.author.id,
        "message": message.message,
    }


@app.get("/api/rooms")
def get_rooms() -> Response | tuple[Response, int]:
    user = _authorized_user()

    if user is None:
        return jsonify(
            error="A valid bearer token is required."
        ), 401

    rooms = [
        membership.room
        for membership in user.room_memberships
    ]

    return jsonify(
        rooms=[
            {
                "id": room.id,
                "name": room.name,
                "last_message": room.messages[-1].message if room.messages else " "
            }
            for room in rooms
        ]
    ), 200


@app.post("/api/rooms/create")
def create_room() -> tuple[Response, int]:
    user = _authorized_user()

    if user is None:
        return jsonify(
            error="A valid bearer token is required."
        ), 401

    body = _json_body()

    if body is None:
        return jsonify(
            error="Request body must be a JSON object."
        ), 400

    room_name = body.get("name")

    if not isinstance(room_name, str):
        return jsonify(
            error="name is required."
        ), 400

    room_name = room_name.strip()

    if not room_name or len(room_name) > 100:
        return jsonify(
            error="name must be between 1 and 100 characters."
        ), 400

    room = Room(
        name=room_name
    )
    user_room = UserRoom(
        user_id=user.id,
        room=room
    )
    try:
        db.session.add(room)
        db.session.add(user_room)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Could not save room.")
        return jsonify(
            error="Could not save room."
        ), 500

    return jsonify(
        room={
            "id": room.id,
            "name": room.name
        }
    ), 201


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
    room_id = body.get("room_id")

    if not message_content or len(message_content) > 500:
        return jsonify(
            error="message must be between 1 and 500 characters."
        ), 400

    # 3. Use the authenticated user, never a client-supplied ID.
    message = Message(
        author_id=user.id,
        room_id=room_id,
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


@app.get("/api/rooms/<int:room_id>/messages")
def get_room_messages(room_id: int):

    user = _authorized_user()

    if user is None:
        return jsonify(
            error="Authentication required."
        ), 401

    if not is_room_member(user.id, room_id):
        return jsonify(
            error="You are not a member of this room."
        ), 403

    messages = (
        db.session.query(Message)
        .filter_by(room_id=room_id)
        .order_by(Message.id.asc())
        .all()
    )

    return jsonify(
        messages=[
            _message_json(message)
            for message in messages
        ]
    ), 200
# --------------------------------------------------
# Current authenticated user
# ------------------------------------------------


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


@socketio.on("join_room")
def handle_join_room(data: Any) -> None:
    # Get the authenticated user from the socket connection.
    user_id = socket_users.get(request.sid)

    if user_id is None:
        emit("error", {
            "message": "You must be authenticated."
        })
        return

    # Validate the received data.
    if not isinstance(data, dict):
        emit("error", {
            "message": "Invalid room data."
        })
        return

    room_id = data.get("room_id")

    # Validate room_id.
    if type(room_id) is not int or room_id <= 0:
        emit("error", {
            "message": "Invalid room ID."
        })
        return

    # Verify membership.
    if not is_room_member(user_id, room_id):
        emit("error", {
            "message": "You are not a member of this room."
        })
        return

    # Join the Socket.IO room.
    join_room(f"chat_{room_id}")

    emit("room_joined", {
        "room_id": room_id,
        "message": "Successfully joined the room."
    })


@socketio.on("send_message")
def handle_send_message(data: Any) -> None:

    # 1. Get the authenticated user.
    user_id = socket_users.get(request.sid)

    user = (
        db.session.get(User, user_id)
        if user_id is not None
        else None
    )

    if user is None:
        emit("error", {
            "message": "Authentication required."
        })
        return

    # 2. Validate the request data.
    if not isinstance(data, dict):
        emit("error", {
            "message": "Message must be a JSON object."
        })
        return

    message_content = data.get("message")
    room_id = data.get("room_id")

    if (
        type(room_id) is not int
        or room_id <= 0
    ):
        emit("error", {
            "message": "Invalid room ID."
        })
        return

    if (
        not isinstance(message_content, str)
        or not message_content.strip()
    ):
        emit("error", {
            "message": "Message must not be empty."
        })
        return

    message_content = message_content.strip()

    if len(message_content) > 500:
        emit("error", {
            "message": "Message is too long."
        })
        return

    # 3. Verify that the sender belongs to the room.
    if not is_room_member(user.id, room_id):
        emit("error", {
            "message": "You are not a member of this room."
        })
        return

    # 4. Save the message.
    message = Message(
        author_id=user.id,
        room_id=room_id,
        message=message_content,
    )

    try:
        db.session.add(message)
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()

        app.logger.exception(
            "Could not save message."
        )

        emit("error", {
            "message": "Could not save message."
        })
        return

    # 5. Send only to users in the same room.
    emit(
        "new_message",
        _message_json(message),
        to=f"chat_{room_id}",
    )


if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
    )
