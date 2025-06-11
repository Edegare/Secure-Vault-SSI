import bson

class GroupDelete:
    def __init__(self, group_id: int):
        self.group_id = group_id

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "group_id": self.group_id
        })

    @staticmethod
    def decode(data: bytes) -> "GroupDelete":
        obj = bson.BSON(data).decode()
        return GroupDelete(obj["group_id"])  
