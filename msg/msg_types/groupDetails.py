import bson

from entities.permission_enum import PERMISSION

class GroupDetails:
    def __init__(self, group_ID: int, group_name: str = None, group_owner: str = None,
                group_permissions: dict[str, PERMISSION] | None = None):
        self.group_ID = group_ID
        self.group_name = group_name
        self.group_owner = group_owner
        self.group_permissions = group_permissions or {}

    def encode(self) -> bytes:
        serialized_group_permissions = []
        for user_id, user_permission in self.group_permissions.items():
            if isinstance(user_permission, PERMISSION):
                user_permission = user_permission.name
            serialized_group_permissions.append((user_id, user_permission))
        
        return bson.BSON.encode({
            "group_ID": self.group_ID,
            "group_name": self.group_name,
            "group_owner": self.group_owner,
            "group_permissions": serialized_group_permissions
        })

    @staticmethod
    def decode(data: bytes) -> "GroupDetails":
        obj = bson.BSON(data).decode()
        return GroupDetails(
            group_ID=obj["group_ID"],
            group_name=obj["group_name"],
            group_owner=obj["group_owner"],
            group_permissions=obj["group_permissions"]
        )