import bson


class GroupCreate:
    def __init__(self, name: str, id: int | None):
        self.name = name
        self.id = id

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "name": self.name,
            "id": self.id,
        })

    @staticmethod
    def decode(data: bytes) -> "GroupCreate":
        obj = bson.BSON(data).decode()
        return GroupCreate(obj["name"], obj["id"])
