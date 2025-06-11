import bson

class Replace:
    def __init__(self, id_to_replace: int, file_path: str, nonce_key_list: dict[str, bytes] | None, other_pub_key_list: dict[str, bytes] | None, file_content: bytes | None):
        self.id_to_replace = id_to_replace
        self.file_path = file_path
        self.nonce_key_list = nonce_key_list
        self.other_pub_key_list = other_pub_key_list
        self.file_content = file_content

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "id_to_replace": self.id_to_replace,
            "file_path": self.file_path,
            "nonce_key_list": self.nonce_key_list,
            "other_pub_key_list": self.other_pub_key_list,
            "file_content": self.file_content
        })

    @staticmethod
    def decode(data: bytes) -> "Replace":
        obj = bson.BSON(data).decode()
        return Replace(obj["id_to_replace"], obj["file_path"], obj["nonce_key_list"], obj["other_pub_key_list"], obj["file_content"])
