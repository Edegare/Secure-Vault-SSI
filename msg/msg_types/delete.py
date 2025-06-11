import bson


class Delete:
    def __init__(self, file_id: int):
        self.file_id = file_id

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "file_id": self.file_id,
        })

    @staticmethod
    def decode(data: bytes) -> "Delete":
        obj = bson.BSON(data).decode()
        return Delete(obj["file_id"])
