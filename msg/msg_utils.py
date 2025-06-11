import bson

from msg.msg_enum import MESSAGE_TYPE
from msg.msg_types.add import Add
from msg.msg_types.list import List
from msg.msg_types.share import Share
from msg.msg_types.delete import Delete
from msg.msg_types.replace import Replace
from msg.msg_types.details import Details
from msg.msg_types.revoke import Revoke
from msg.msg_types.read import Read
from msg.msg_types.groupCreate import GroupCreate
from msg.msg_types.groupDelete import GroupDelete
from msg.msg_types.groupDetails import GroupDetails
from msg.msg_types.groupAddUser import GroupAddUser
from msg.msg_types.groupDeleteUser import GroupDeleteUser
from msg.msg_types.groupList import GroupList
from msg.msg_types.groupAdd import GroupAdd
from msg.msg_types.alert import Alert

class Message:
    TYPE_CLASS_MAP = {
        MESSAGE_TYPE.ADD: Add,
        MESSAGE_TYPE.READ: Read,
        MESSAGE_TYPE.DELETE: Delete,
        MESSAGE_TYPE.REVOKE: Revoke,
        MESSAGE_TYPE.LIST: List,
        MESSAGE_TYPE.DETAILS: Details,
        MESSAGE_TYPE.SHARE: Share,
        MESSAGE_TYPE.GROUP_DELETE: GroupDelete,
        MESSAGE_TYPE.GROUP_DETAILS: GroupDetails,
        MESSAGE_TYPE.GROUP_LIST: GroupList,
        MESSAGE_TYPE.GROUP_DELETE_USER: GroupDeleteUser,
        MESSAGE_TYPE.GROUP_ADD_USER: GroupAddUser,
        MESSAGE_TYPE.GROUP_ADD: GroupAdd,
        MESSAGE_TYPE.GROUP_CREATE: GroupCreate,
        MESSAGE_TYPE.REPLACE: Replace,
        MESSAGE_TYPE.ERROR: Alert,
        MESSAGE_TYPE.SUCCESS: Alert,
    }

    def __init__(self, sender: str, header: MESSAGE_TYPE, content: bytes):
        self.sender = sender
        self.header = header
        self.content = content

    def encode(self) -> bytes:
        return bson.BSON.encode({
            "sender": self.sender,
            "header": self.header.value,  # store as integer
            "content": self.content
        })

    @staticmethod
    def decode(data: bytes) -> "Message":
        obj = bson.BSON(data).decode()

        return Message(
            sender=obj["sender"],
            header=MESSAGE_TYPE(obj["header"]),  # convert back to enum
            content=obj["content"]
        )

    def get_content_object(self) -> object:
        cls = self.TYPE_CLASS_MAP.get(self.header)
        if cls is None:
            raise ValueError(f"Unknown message type: {self.header}")
        return cls.decode(self.content)
