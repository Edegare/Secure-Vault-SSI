import bson

class Alert:
    def __init__(self, message: str):
        self.message = message

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "message": self.message
        })

    @staticmethod
    def decode(data: bytes) -> "Alert":
        obj = bson.BSON(data).decode()
        return Alert(message=obj["message"])