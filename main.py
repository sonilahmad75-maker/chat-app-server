import os
import secrets
from datetime import timedelta
from typing import Any

from flask import Flask, Response, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import Integer, String
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY") or secrets.token_hex(32)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///users.db"
)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
db.init_app(app)


class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    email: Mapped[str] = mapped_column(
        String(254), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(300), nullable=False)
    #
    posts = db.relationship("Message", back_populates="author")


class Message(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    mesage: Mapped[str] = mapped_column(String(500))
    #
    author = db.relationship("User", back_populates="posts")

# 
# with app.app_context():
#     db.create_all()

_TOKEN_MAX_AGE = int(timedelta(days=1).total_seconds())


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="flutter-auth")


def _create_token(user: User) -> str:
    return _serializer().dumps({"user_id": user.id})


def _user_json(user: User) -> dict[str, Any]:
    return {"id": user.id, "name": user.name, "email": user.email}


def _json_body() -> dict[str, Any] | None:
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def _authorized_user() -> User | None:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None

    try:
        payload = _serializer().loads(token, max_age=_TOKEN_MAX_AGE)
    except BadSignature:
        return None

    if not isinstance(payload, dict):
        return None
    user_id = payload.get("user_id")
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        return None
    return db.session.get(User, user_id)


@app.post("/api/register")
def register() -> tuple[Response, int]:
    body = _json_body()
    if body is None:
        return jsonify(error="Request body must be a JSON object."), 400

    name = body.get("name")
    email = body.get("email")
    password = body.get("password")
    if (
        not isinstance(name, str)
        or not isinstance(email, str)
        or not isinstance(password, str)
    ):
        return jsonify(error="name, email, and password are required."), 400

    name = name.strip()
    email = email.strip().lower()
    if not name or len(name) > 50:
        return jsonify(error="name must be between 1 and 50 characters."), 400
    if (
        len(email) > 254
        or email.count("@") != 1
        or not email.partition("@")[2]
        or "." not in email.partition("@")[2]
    ):
        return jsonify(error="A valid email address is required."), 400
    if len(password) < 8:
        return jsonify(error="password must be at least 8 characters."), 400

    user = User()
    user.name = name
    user.email = email
    user.password_hash = generate_password_hash(password)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify(error="An account with this email already exists."), 409

    return jsonify(user=_user_json(user), token=_create_token(user)), 201


@app.post("/api/login")
def login() -> Response | tuple[Response, int]:
    body = _json_body()
    if body is None:
        return jsonify(error="Request body must be a JSON object."), 400

    email = body.get("email")
    password = body.get("password")
    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify(error="email and password are required."), 400

    user = db.session.query(User).filter_by(
        email=email.strip().lower()).first()
    if user is None or not check_password_hash(user.password_hash, password):
        return jsonify(error="Invalid email or password."), 401

    return jsonify(user=_user_json(user), token=_create_token(user)), 200


@app.get("/api/me")
def me() -> Response | tuple[Response, int]:
    user = _authorized_user()
    if user is None:
        return jsonify(error="A valid bearer token is required."), 401
    return jsonify(user=_user_json(user))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
