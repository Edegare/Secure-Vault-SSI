import bson


class Add:
    def __init__(self, file_name: str, file_owner: str, encrypted_file: bytes, encrypted_nonce_key: bytes):
        self.file_name = file_name
        self.file_owner = file_owner
        self.file = encrypted_file
        self.nonce_key = encrypted_nonce_key

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "file_name": self.file_name,
            "file_owner": self.file_owner,
            "file": self.file,
            "nonce_key": self.nonce_key
        })

    @staticmethod
    def decode(data: bytes) -> "Add":
        obj = bson.BSON(data).decode()
        return Add(obj["file_name"], obj["file_owner"], obj["file"], obj["nonce_key"])
