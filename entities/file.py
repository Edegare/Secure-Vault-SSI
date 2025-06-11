from entities.permission_enum import PERMISSION

class File:
    next_id = 0

    def __init__(self, name: str, owner: str, content: bytes, user_permissions, group_permissions, keys):
        """
        ID: unique identifier
        name: common name
        owner: owner (user)
        content: ciphered content
        user_permissions: a dictionary that maps every user ID to a permission
        group_permissions: a list that contains every group ID that has access to the file
        keys: a dictionary that maps every user ID to the encrypted simetric key
        """
        self.ID = File.next_id
        File.next_id += 1

        self.name = name
        self.owner = owner
        self.content = content
        self.user_permissions = user_permissions
        self.group_permissions = group_permissions
        self.keys = keys

    def encode(self) -> dict:
        """Encode the File object into a BSON-compatible dictionary."""
        return {
            "ID": self.ID,
            "name": self.name,
            "owner": self.owner,
            "content": self.content,
            "user_permissions": {user: perm.value for user, perm in self.user_permissions.items()},
            "group_permissions": self.group_permissions,
            "keys": self.keys
        }

    @staticmethod
    def decode(data: dict) -> "File":
        """Decode a BSON-compatible dictionary into a File object."""
        user_permissions = {user: PERMISSION(perm) for user, perm in data["user_permissions"].items()}
        file = File(data["name"], data["owner"], data["content"], user_permissions, data["group_permissions"], data["keys"])
        file.ID = int(data["ID"])
        File.next_id = max(File.next_id, file.ID + 1)
        return file