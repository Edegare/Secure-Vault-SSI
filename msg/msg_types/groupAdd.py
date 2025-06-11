import bson

class GroupAdd:
    def __init__(self, group_id: int, file_path: str, nonce_key_list: dict[str, bytes] | None, other_pub_key_list: dict[str, bytes] | None, file_content: bytes | None):
        self.group_id = group_id
        self.file_path = file_path
        self.nonce_key_list = nonce_key_list
        self.other_pub_key_list = other_pub_key_list
        self.file_content = file_content

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "group_id": self.group_id,
            "file_path": self.file_path,
            "nonce_key_list": self.nonce_key_list,
            "other_pub_key_list": self.other_pub_key_list,
            "file_content": self.file_content
        })

    @staticmethod
    def decode(data: bytes) -> "GroupAdd":
        obj = bson.BSON(data).decode()
        return GroupAdd(obj["group_id"], obj["file_path"], obj["nonce_key_list"], obj["other_pub_key_list"], obj["file_content"])
