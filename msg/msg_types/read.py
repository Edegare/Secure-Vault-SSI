import bson


class Read:
    def __init__(self, file_id: int, file_name: str | None, encrypted_file: bytes | None, encrypted_nonce_key: bytes | None):
        self.file_id = file_id
        self.file_name = file_name
        self.file = encrypted_file
        self.nonce_key = encrypted_nonce_key

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "file_id": self.file_id,
            "file_name": self.file_name,
            "file": self.file,
            "nonce_key": self.nonce_key
        })

    @staticmethod
    def decode(data: bytes) -> "Read":
        obj = bson.BSON(data).decode()
        return Read(obj["file_id"], obj["file_name"], obj["file"], obj["nonce_key"])
