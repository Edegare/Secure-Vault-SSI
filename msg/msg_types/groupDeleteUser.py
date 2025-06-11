import bson

class GroupDeleteUser:
    def __init__(self, group_id: int, user_id: str):
        self.group_id = group_id
        self.user_id = user_id

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "group_id": self.group_id,
            "user_id": self.user_id,
        })

    @staticmethod
    def decode(data: bytes) -> "GroupDeleteUser":
        obj = bson.BSON(data).decode()
        return GroupDeleteUser(obj["group_id"], obj["user_id"])