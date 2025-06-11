import bson

class Details:
    def __init__(self, file_id: int, name: str = None, owner: str = None, 
                 user_permissions: dict = None, group_permissions: dict = None):
        self.file_id = file_id
        self.name = name
        self.owner = owner
        self.user_permissions = user_permissions or {}  # {user_id : perm}
        self.group_permissions = group_permissions or {}  # {group_id : {user_id : perm}}

    def encode(self) -> bytes:
        ser_user_perms = {}
        for user, perm in self.user_permissions.items():
            ser_user_perms[user] = perm.name

        return bson.BSON.encode({
            "file_id": self.file_id,
            "name": self.name,
            "owner": self.owner,
            "user_permissions": ser_user_perms,
            "group_permissions": self.group_permissions
        })


    @staticmethod
    def decode(data: bytes) -> "Details":
        obj = bson.BSON(data).decode()
        return Details(
            file_id=obj["file_id"],
            name=obj["name"],
            owner=obj["owner"],
            user_permissions=obj["user_permissions"],
            group_permissions=obj["group_permissions"]
        )