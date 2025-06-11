import bson
from entities.permission_enum import PERMISSION

class List:
    def __init__(self, id: str, isUser: bool, availableFiles: list[tuple[str, int, str, PERMISSION]] | None):
        self.id = id
        self.isUser = isUser
        self.availableFiles = availableFiles

    def encode(self) -> bytes:
        # Convert PERMISSION enum to string for serialization
        serialized_files = [
            (file[0], file[1], file[2], file[3].value if isinstance(file[3], PERMISSION) else file[3])
            for file in self.availableFiles
        ] if self.availableFiles else None

        return bson.BSON.encode({
            "id": self.id,
            "isUser": self.isUser,
            "availableFiles": serialized_files,
        })

    @staticmethod
    def decode(data: bytes) -> "List":
        obj = bson.BSON(data).decode()

        # Convert strings back to PERMISSION enum
        deserialized_files = [
            (file[0], file[1], file[2], PERMISSION(file[3]) if isinstance(file[3], int) else file[3])
            for file in obj["availableFiles"]
        ] if obj["availableFiles"] else None

        return List(obj["id"], obj["isUser"], deserialized_files)
