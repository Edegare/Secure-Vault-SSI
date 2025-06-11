import bson

from entities.permission_enum import PERMISSION

class GroupList:
    def __init__(self, groups: list= None):
        self.groups = groups or []  # (group_id, group_name, permission)

    def encode(self) -> bytes:
        ser_groups = []
        for group_id, group_name, permission in self.groups:
            if isinstance(permission, PERMISSION):
                permission = permission.name
            ser_groups.append((group_id, group_name, permission))
        
        return bson.BSON.encode({
            "groups": ser_groups
        })

    @staticmethod
    def decode(data: bytes) -> "GroupList":
        obj = bson.BSON(data).decode()
        return GroupList(groups=obj["groups"])