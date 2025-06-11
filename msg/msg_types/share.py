import bson
from entities.permission_enum import PERMISSION

class Share:
    def __init__(self, file_id: int, user_id: str, permission: PERMISSION, nonce_key: bytes | None, other_pub_key: bytes | None):
        self.file_id = file_id
        self.user_id = user_id
        self.permission = permission
        self.nonce_key = nonce_key
        self.other_pub_key = other_pub_key

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "file_id": self.file_id,
            "user_id": self.user_id,
            "permission": self.permission.value,
            "nonce_key": self.nonce_key,
            "other_pub_key": self.other_pub_key
        })

    @staticmethod
    def decode(data: bytes) -> "Share":
        obj = bson.BSON(data).decode()
        return Share(
            file_id=int(obj["file_id"]),
            user_id=obj["user_id"],
            permission=PERMISSION(obj["permission"]),
            nonce_key=obj["nonce_key"],
            other_pub_key=obj["other_pub_key"]
        )
