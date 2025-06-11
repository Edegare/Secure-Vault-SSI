import bson
from entities.permission_enum import PERMISSION


class GroupAddUser:
    def __init__(self, group_id: int, user_id: str, permissions: PERMISSION, other_pub_key: bytes | None = None, file_nonce_key_list: dict[str, bytes] | None = None):
        self.group_id = group_id
        self.user_id = user_id
        self.permissions = permissions
        self.other_pub_key = other_pub_key
        self.file_nonce_key_list = file_nonce_key_list

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "group_id": self.group_id,
            "user_id": self.user_id,
            "permissions": self.permissions.value,  # store as integer
            "other_pub_key": self.other_pub_key,
            "file_nonce_key_list": self.file_nonce_key_list
        })

    @staticmethod
    def decode(data: bytes) -> "GroupAddUser":
        obj = bson.BSON(data).decode()
        return GroupAddUser(obj["group_id"], obj["user_id"], PERMISSION(obj["permissions"]), obj["other_pub_key"], obj["file_nonce_key_list"])
