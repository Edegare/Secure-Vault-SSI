from entities.permission_enum import PERMISSION

class Group:
    next_id = 0

    def __init__(self, owner, name, users, user_permissions):
        """
        ID: unique identifier
        owner: owner (user)
        name: common name
        users: a list of the group's users (ID)
        user_permissions: a dictionary that maps each user ID to a permission
        """
        self.ID = Group.next_id
        Group.next_id += 1

        self.owner = owner
        self.name = name
        self.users = users
        self.user_permissions = user_permissions

    def encode(self) -> dict:
        """Encode the Group object into a BSON-compatible dictionary."""
        return {
            "ID": self.ID,
            "owner": self.owner,
            "name": self.name,
            "users": self.users,
            "user_permissions": {user: perm.value for user, perm in self.user_permissions.items()}
        }

    @staticmethod
    def decode(data: dict) -> "Group":
        """Decode a BSON-compatible dictionary into a Group object."""
        user_permissions = {user: PERMISSION(perm) for user, perm in data["user_permissions"].items()}
        group = Group(data["owner"], data["name"], data["users"], user_permissions)
        group.ID = data["ID"]
        Group.next_id = max(Group.next_id, group.ID + 1)
        return group
