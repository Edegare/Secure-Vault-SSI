import bson


class Revoke:
    def __init__(self, file_id: int, user_id: str):
        self.file_id = file_id
        self.user_id = user_id

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "file_id": self.file_id,
            "user_id": self.user_id,
        })

    @staticmethod
    def decode(data: bytes) -> "Revoke":
        obj = bson.BSON(data).decode()
        return Revoke(obj["file_id"], obj["user_id"])
