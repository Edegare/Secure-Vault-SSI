from utils.cert_utils import cert_to_bytes, bytes_to_cert

class User:
    def __init__(self, ID, name, groups, cert):
        """
        ID: unique identifier
        name: common name
        groups: a list of the user's groups (ID)
        """
        self.ID = ID
        self.name = name
        self.groups = groups
        self.cert = cert

    def encode(self) -> dict:
        """Encode the User object into a BSON-compatible dictionary."""
        return {
            "ID": self.ID,
            "name": self.name,
            "groups": self.groups,
            "cert": cert_to_bytes(self.cert)
        }

    @staticmethod
    def decode(data: dict) -> "User":
        """Decode a BSON-compatible dictionary into a User object."""
        cert = bytes_to_cert(data["cert"])
        return User(data["ID"], data["name"], data["groups"], cert)
