import unittest

import main
from werkzeug.security import generate_password_hash


class ChatApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        main.app.config.update(
            TESTING=True,
            SQLALCHEMY_DATABASE_URI="sqlite://",
        )

    def setUp(self) -> None:
        with main.app.app_context():
            main.db.drop_all()
            main.db.create_all()
            self.sender = main.User(
                name="Sender",
                email="sender@example.test",
                password_hash=generate_password_hash("password123"),
            )
            self.recipient = main.User(
                name="Recipient",
                email="recipient@example.test",
                password_hash=generate_password_hash("password123"),
            )
            self.outsider = main.User(
                name="Outsider",
                email="outsider@example.test",
                password_hash=generate_password_hash("password123"),
            )
            main.db.session.add_all([
                self.sender,
                self.recipient,
                self.outsider,
            ])
            main.db.session.commit()
            self.sender_id = self.sender.id
            self.recipient_id = self.recipient.id
            self.sender_token = main._create_token(self.sender)
            self.outsider_token = main._create_token(self.outsider)

        self.client = main.app.test_client()

    def tearDown(self) -> None:
        with main.app.app_context():
            main.db.session.remove()
            main.db.drop_all()

    @staticmethod
    def auth(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def test_create_or_get_direct_room(self) -> None:
        response = self.client.post(
            "/api/create-or-get-room",
            json={"email": " RECIPIENT@example.test "},
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(response.status_code, 200)
        room_id = response.get_json()["room_id"]

        second_response = self.client.post(
            "/api/create-or-get-room",
            json={"email": "recipient@example.test"},
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(second_response.status_code, 200)
        self.assertEqual(second_response.get_json()["room_id"], room_id)

        with main.app.app_context():
            room = main.db.session.get(main.Room, room_id)
            self.assertIsNotNone(room)
            self.assertEqual(room.is_group, 0)
            self.assertEqual(len(room.user_memberships), 2)

    def test_create_or_get_rejects_self_and_unknown_user(self) -> None:
        self_response = self.client.post(
            "/api/create-or-get-room",
            json={"email": "sender@example.test"},
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(self_response.status_code, 400)

        missing_response = self.client.post(
            "/api/create-or-get-room",
            json={"email": "missing@example.test"},
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(missing_response.status_code, 404)

    def test_room_creation_validates_recipient(self) -> None:
        missing_response = self.client.post(
            "/api/rooms/create",
            json={"name": "Chat"},
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(missing_response.status_code, 400)

        unknown_response = self.client.post(
            "/api/rooms/create",
            json={"name": "Chat", "reciver_email": "missing@example.test"},
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(unknown_response.status_code, 404)

        created_response = self.client.post(
            "/api/rooms/create",
            json={"name": "Chat", "reciver_email": "recipient@example.test"},
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(created_response.status_code, 201)

    def test_rest_message_send_requires_membership_and_valid_room_id(self) -> None:
        with main.app.app_context():
            room = main.Room(name="Private")
            room.user_memberships.extend([
                main.UserRoom(user_id=self.sender_id),
                main.UserRoom(user_id=self.recipient_id),
            ])
            main.db.session.add(room)
            main.db.session.commit()
            room_id = room.id

        outsider_response = self.client.post(
            "/api/send-message",
            json={"room_id": room_id, "message": "Not allowed"},
            headers=self.auth(self.outsider_token),
        )
        self.assertEqual(outsider_response.status_code, 403)

        invalid_room_response = self.client.post(
            "/api/send-message",
            json={"room_id": "not-an-id", "message": "Invalid room"},
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(invalid_room_response.status_code, 400)

        allowed_response = self.client.post(
            "/api/send-message",
            json={"room_id": room_id, "message": "Allowed"},
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(allowed_response.status_code, 201)

        with main.app.app_context():
            self.assertEqual(main.db.session.query(main.Message).count(), 1)

    def test_negative_room_message_path_returns_bad_request(self) -> None:
        response = self.client.get(
            "/api/rooms/-1/messages",
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(response.status_code, 400)

    def test_room_list_uses_latest_message(self) -> None:
        with main.app.app_context():
            room = main.Room(name="Chat")
            room.user_memberships.append(
                main.UserRoom(user_id=self.sender_id)
            )
            main.db.session.add(room)
            main.db.session.flush()
            main.db.session.add_all([
                main.Message(
                    author_id=self.sender_id,
                    room_id=room.id,
                    message="Earlier",
                ),
                main.Message(
                    author_id=self.sender_id,
                    room_id=room.id,
                    message="Latest",
                ),
            ])
            main.db.session.commit()

        response = self.client.get(
            "/api/rooms",
            headers=self.auth(self.sender_token),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["rooms"][0]["last_message"],
            "Latest",
        )

    def test_database_initialization_command(self) -> None:
        result = main.app.test_cli_runner().invoke(args=["init-db"])
        self.assertEqual(result.exit_code, 0, result.output)


if __name__ == "__main__":
    unittest.main()
