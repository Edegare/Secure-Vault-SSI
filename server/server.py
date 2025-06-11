import asyncio
import os
import argparse
import bson

from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from utils.ui import create_account
from utils.utils import couple, unpair
from utils.logger import Logger
from utils.key_utils import pubkey_bytes
from utils.cert_utils import bytes_to_cert, cert_to_bytes, validate_cert, validate_signature, sign, get_userdata, cert_load

from msg.msg_utils import Message
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

from entities.user import User
from entities.file import File
from entities.group import Group
from entities.permission_enum import PERMISSION

password = "7GNrvJPuO4zdT6s3VGm9qH1F5Ej0Q4QgIkyhqhpLq9KnmJ64lY"

conn_port = 7777
max_msg_size = 9999

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

keystore_filepath = "vault_sv.p12"
CA_cert = cert_load("crt/ca.crt")

groups = {}
users = {}
files = {}

db_filepath = "out/db.bin"

def save_to_db():
    """
    Save the current state of groups, users, and files to a BSON file.
    This function ensures the data is persisted for future use.
    """
    try:
        os.makedirs(os.path.dirname(db_filepath), exist_ok=True)
        with open(db_filepath, "wb") as db_file:
            bson_data = bson.BSON.encode({
                "groups": {str(gid): group.encode() for gid, group in groups.items()},
                "users": {uid: user.encode() for uid, user in users.items()},
                "files": {str(fid): file.encode() for fid, file in files.items()}
            })
            db_file.write(bson_data)
        log.success("Database saved", f"Data saved to {db_filepath}")
    except Exception as e:
        log.error("Failed to save database", f"Error: {e}")

def load_from_db():
    """
    Load the state of groups, users, and files from a BSON file.
    If the file does not exist or is corrupted, appropriate error handling is performed.
    """
    global groups, users, files
    try:
        with open(db_filepath, "rb") as db_file:
            data = bson.BSON(db_file.read()).decode()
            groups = {int(gid): Group.decode(group) for gid, group in data.get("groups", {}).items()}
            users = {uid: User.decode(user) for uid, user in data.get("users", {}).items()}
            files = {int(fid): File.decode(file) for fid, file in data.get("files", {}).items()}
        log.success("Database loaded", f"Data loaded from {db_filepath}")
    except FileNotFoundError:
        log.error("Database file not found", f"{db_filepath} does not exist")
    except bson.errors.BSONError:
        log.error("Corrupted database file", f"{db_filepath} is corrupted")
    except Exception as e:
        log.error("Failed to load database", f"Error: {e}")

class ServerWorker(object):
    """
    Implements the functionality of the server, including handling messages,
    managing users, groups, and files, and performing cryptographic operations.
    """

    def __init__(self, addr=None):
        """
        Initialize the server worker with the given address.
        """
        self.addr = addr
        self.msg_cnt = 0

    def set_RSA_priv_key(self, RSA_priv_key):
        """
        Set the RSA private key for the server.
        """
        self.RSA_priv_key = RSA_priv_key

    def set_sv_cert(self, sv_cert):
        """
        Set the server's certificate.
        """
        self.sv_cert = sv_cert

    def set_sv_id(self):
        """
        Set the server's unique identifier based on its certificate.
        """
        nameAttribute = self.sv_cert.subject.get_attributes_for_oid(
            NameOID.PSEUDONYM)
        assert len(nameAttribute) == 1
        self.id = nameAttribute.pop().value

    def sign(self, message):
        """
        Sign a message using the server's RSA private key.
        """
        return sign(self.RSA_priv_key, message)

    def getPublic(self):
        """
        Generate and return the server's public key for Diffie-Hellman key exchange.
        """
        pn = dh.DHParameterNumbers(p, g)
        self.private = pn.parameters().generate_private_key()
        self.public = self.private.public_key()
        return self.public

    def generateShared(self, public):
        """
        Generate a shared secret using the client's public key.
        """
        publicKey = load_pem_public_key(public)
        if isinstance(publicKey, dh.DHPublicKey):
            self.shared = self.private.exchange(publicKey)

    def encrypt_msg(self, msg_out: Message) -> bytes:
        """
        Encrypt a message using AES-GCM with a derived shared key.
        """
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(self.shared)

        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, msg_out.encode(), None) + nonce
        return ct

    def trigger_alert(self, alertString: str, verboseAlertString: str, alert_type: MESSAGE_TYPE) -> Message:
        """
        Trigger an alert message with the specified type and content.
        """
        if alert_type == MESSAGE_TYPE.ERROR:
            log.warn(alertString, verboseAlertString)
        else:
            log.success(alertString, verboseAlertString)

        alert_message = alertString if log.level == 0 else verboseAlertString
        alert = Alert(alert_message)
        return Message(self.id, alert_type, alert.encode())

    def handleMessage(self, struct_msg):
        """
        Handle incoming messages by decoding and routing them to the appropriate handler.
        """
        m = Message.decode(struct_msg)
        msg_type = m.header

        if msg_type == MESSAGE_TYPE.ADD:
            return self.handle_add(m)
        if msg_type == MESSAGE_TYPE.READ:
            return self.handle_read(m)
        if msg_type == MESSAGE_TYPE.LIST:
            return self.handle_list(m)
        if msg_type == MESSAGE_TYPE.REPLACE:
            return self.handle_replace(m)
        if msg_type == MESSAGE_TYPE.SHARE:
            return self.handle_share(m)
        if msg_type == MESSAGE_TYPE.GROUP_LIST:
            return self.handle_group_list(m)
        if msg_type == MESSAGE_TYPE.DETAILS:
            return self.handle_details(m)
        if msg_type == MESSAGE_TYPE.GROUP_DELETE_USER:
            return self.handle_group_delete_user(m)
        if msg_type == MESSAGE_TYPE.GROUP_ADD_USER:
            return self.handle_group_add_user(m)
        if msg_type == MESSAGE_TYPE.GROUP_ADD:
            return self.handle_group_add(m)
        if msg_type == MESSAGE_TYPE.GROUP_CREATE:
            return self.handle_group_create(m)
        if msg_type == MESSAGE_TYPE.GROUP_DELETE:
            return self.handle_group_delete(m)
        if msg_type == MESSAGE_TYPE.GROUP_DETAILS:
            return self.handle_group_details(m)
        if msg_type == MESSAGE_TYPE.DELETE:
            return self.handle_delete(m)
        if msg_type == MESSAGE_TYPE.REVOKE:
            return self.handle_revoke(m)

        msg_out = self.trigger_alert("Unknown message type",
                                     f"Message type {msg_type} not recognized",
                                     MESSAGE_TYPE.ERROR)
        return self.encrypt_msg(msg_out)

    def handle_add(self, message):
        """
        Handle the addition of a new file to the server.
        """
        content = message.get_content_object()
        assert isinstance(content, Add)

        user_permissions = {}
        user_permissions[message.sender] = PERMISSION.RW

        keys_dict = {}
        keys_dict[message.sender] = content.nonce_key

        file = File(content.file_name, content.file_owner,
                    content.file, user_permissions, {}, keys_dict)

        files[file.ID] = file
        msg_out = self.trigger_alert("File added",
                                     f"File {file.name} (whose file ID is {file.ID}) was added to the server by {message.sender}",
                                     MESSAGE_TYPE.SUCCESS)
        return self.encrypt_msg(msg_out)

    def handle_read(self, message):
        """
        Handle a request to read a file from the server.
        """
        content = message.get_content_object()
        assert isinstance(content, Read)

        file_id_to_read = content.file_id
        log.info("A read request was issued", f"{message.sender} wants to read file {file_id_to_read}")

        file = files.get(file_id_to_read)
        if file is None:
            msg_out = self.trigger_alert("File does not exist",
                                         f"File {file_id_to_read} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        sender_permissions = file.user_permissions.get(message.sender)

        if sender_permissions is None or sender_permissions == PERMISSION.W:
            has_access = False  # Flag to track access

            for groupID in file.group_permissions:
                group = groups.get(groupID)

                if group is None:
                    msg_out = self.trigger_alert("Group does not exist",
                                                 f"Group {groupID} does not exist",
                                                 MESSAGE_TYPE.ERROR)
                    return self.encrypt_msg(msg_out)

                sender_permissions = group.user_permissions.get(message.sender)
                if sender_permissions is not None and sender_permissions != PERMISSION.W:
                    has_access = True
                    break

            if not has_access:
                msg_out = self.trigger_alert("Sender does not have access to file",
                                             f"{message.sender} does not have read access to file {file_id_to_read}",
                                             MESSAGE_TYPE.ERROR)
                return self.encrypt_msg(msg_out)

        content = Read(file_id_to_read, file.name,
                       file.content, file.keys[message.sender])
        message = Message(self.id, MESSAGE_TYPE.READ, content.encode())

        return self.encrypt_msg(message)

    def handle_list(self, message):
        """
        Handle a request to list files accessible to a user or group.
        """
        content = message.get_content_object()
        assert isinstance(content, List)

        id = content.id
        isUser = content.isUser
        availableFiles = []

        if isUser:
            user = users.get(id)

            if user is None:
                msg_out = self.trigger_alert("User does not exist",
                                             f"User {id} does not exist",
                                             MESSAGE_TYPE.ERROR)
                return self.encrypt_msg(msg_out)

            for file in files.values():
                if id in file.user_permissions:
                    availableFiles.append(
                        (id, file.ID, file.name, file.user_permissions[id]))
                else:
                    for groupID in user.groups:
                        if groupID in file.group_permissions:
                            group = groups.get(groupID)

                            if group is None:
                                msg_out = self.trigger_alert("Group does not exist",
                                                             f"Group {groupID} does not exist",
                                                             MESSAGE_TYPE.ERROR)
                                return self.encrypt_msg(msg_out)

                            availableFiles.append(
                                (id, file.ID, file.name, group.user_permissions[id]))
                            break
        else:
            try:
                group_id = int(id)
            except ValueError:
                msg_out = self.trigger_alert("Invalid group ID",
                                             f"Group ID '{id}' is not a valid integer",
                                             MESSAGE_TYPE.ERROR)
                return self.encrypt_msg(msg_out)
            group = groups.get(group_id)

            if group is None:
                msg_out = self.trigger_alert("Group does not exist",
                                             f"Group {group_id} does not exist",
                                             MESSAGE_TYPE.ERROR)
                return self.encrypt_msg(msg_out)


            for file in files.values():
                if group_id in file.group_permissions:
                    for user_id, user_permissions in group.user_permissions.items():
                        availableFiles.append(
                            (user_id, file.ID, file.name, user_permissions))

        content = List(id, isUser, availableFiles)
        message = Message(self.id, MESSAGE_TYPE.LIST, content.encode())

        return self.encrypt_msg(message)

    def handle_replace(self, message):
        """
        Handle a request to replace an existing file on the server.
        """
        content = message.get_content_object()
        assert isinstance(content, Replace)


        file_id = content.id_to_replace
        file_path = content.file_path
        nonce_key_list = content.nonce_key_list

        file = files.get(file_id)
        if file is None:
            msg_out = self.trigger_alert("File does not exist",
                                         f"File {content.id_to_replace} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        user = users.get(message.sender)
        if user is None:
            msg_out = self.trigger_alert("User does not exist",
                                         f"User {message.sender} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)
        
        has_replace_permission = False
        
        # owner permissions in the file
        if file.owner == message.sender:
            has_replace_permission = True

        # user permissions in the file
        if not has_replace_permission:
            user_permission = file.user_permissions.get(message.sender)
            if user_permission is not None:
                if user_permission != PERMISSION.R:
                    has_replace_permission = True

        # user group permissions in the file in question
        if not has_replace_permission:
            for group_id in user.groups:
                if group_id in file.group_permissions:
                    g = groups.get(group_id)
                    if g is None:
                        msg_out = self.trigger_alert("Group does not exist",
                                                    f"Group {group_id} does not exist",
                                                    MESSAGE_TYPE.ERROR)
                        return self.encrypt_msg(msg_out)

                    group_permission = g.user_permissions.get(message.sender)
                    if group_permission is not None:
                        if group_permission != PERMISSION.R:
                            has_replace_permission = True
                        break

        if not has_replace_permission:
            msg_out = self.trigger_alert("User does not have replace access to the file",
                                         f"{message.sender} does not have replace access to file {content.id_to_replace}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)
        
        # first message from the client
        if nonce_key_list is None:
            
            pub_key_list = {}

            # get the public keys of the users that have access to the file
            for user_id in file.keys.keys():
                user = users.get(user_id)
                if user is None:
                    msg_out = self.trigger_alert("User does not exist",
                                                 f"User {user_id} does not exist",
                                                 MESSAGE_TYPE.ERROR)
                    return self.encrypt_msg(msg_out)

                pub_key_list[user_id] = (pubkey_bytes(user.cert.public_key()))

            response = Replace(
                id_to_replace=file_id,
                file_path=file_path,
                nonce_key_list=None,
                other_pub_key_list=pub_key_list,
                file_content=None
            )

            msg_out = Message(
                self.id, MESSAGE_TYPE.REPLACE, response.encode())

            return self.encrypt_msg(msg_out)
        
        # second message from the client
        else:
            file.name = os.path.basename(file_path)
            file.content = content.file_content
            file.keys = nonce_key_list

            msg_out = self.trigger_alert("File replaced",
                                         f"File {file.name} (whose file ID is {file.ID}) was replaced by {message.sender}",
                                         MESSAGE_TYPE.SUCCESS)
            return self.encrypt_msg(msg_out)

    def handle_share(self, message):
        """
        Handle a request to share a file with another user.
        """
        content = message.get_content_object()
        assert isinstance(content, Share)

        file_id_to_share = content.file_id
        file = files.get(file_id_to_share)

        if file is None:
            msg_out = self.trigger_alert("File does not exist",
                                         f"File {file_id_to_share} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if content.nonce_key is None and content.other_pub_key is None:
            if message.sender != file.owner:
                msg_out = self.trigger_alert("User does not have share permission",
                                             f"{message.sender} does not have permission to share file {file_id_to_share}",
                                             MESSAGE_TYPE.ERROR)
                return self.encrypt_msg(msg_out)

            encrypted_nonce_key = file.keys.get(message.sender)
            if encrypted_nonce_key is None:
                msg_out = self.trigger_alert("No key found for sender",
                                             f"No key found for {message.sender}",
                                             MESSAGE_TYPE.ERROR)
                return self.encrypt_msg(msg_out)

            user = users.get(content.user_id)
            if user is None:
                msg_out = self.trigger_alert("User does not exist",
                                             f"User {content.user_id} does not exist",
                                             MESSAGE_TYPE.ERROR)
                return self.encrypt_msg(msg_out)

            other_pub_key_bytes = pubkey_bytes(user.cert.public_key())

            response = Share(
                file_id=int(file_id_to_share),
                user_id=content.user_id,
                permission=content.permission,
                nonce_key=encrypted_nonce_key,
                other_pub_key=other_pub_key_bytes
            )

            msg_out = Message(self.id, MESSAGE_TYPE.SHARE, response.encode())

            return self.encrypt_msg(msg_out)

        elif content.nonce_key is not None:
            file.user_permissions[content.user_id] = PERMISSION(
                content.permission)
            file.keys[content.user_id] = content.nonce_key

            msg_out = self.trigger_alert("File shared",
                                         f"{message.sender} shared file {file_id_to_share} with {content.user_id} with {content.permission} permission",
                                         MESSAGE_TYPE.SUCCESS)
            return self.encrypt_msg(msg_out)

    def handle_group_list(self, message):
        """
        Handle a request to list groups a user belongs to.
        """
        log.info("A group_list request was issued", 
                    f"{message.sender} requested to list his groups")

        user = users.get(message.sender)
        if user is None:
            msg_out = self.trigger_alert("User does not exist",
                                         f"User {message.sender} does not exist.",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)
        
        group_info = []
        for group_id in user.groups:
            group = groups.get(group_id)
            if not group:
                msg_out = self.trigger_alert("Group does not exist",
                                             f"Group {group_id} does not exist",
                                             MESSAGE_TYPE.ERROR)
                return self.encrypt_msg(msg_out)
            
            permission = group.user_permissions.get(message.sender)
            if not permission:
                group_info.append((group_id, group.name, "ERROR")) 
                msg_out = self.trigger_alert("Sender does not have permission",
                                             f"{message.sender} does not have permission in group {group_id}",
                                             MESSAGE_TYPE.ERROR)
                return self.encrypt_msg(msg_out)
            
            group_info.append((group_id, group.name, permission))

        response = GroupList(groups=group_info)
        msg_out = Message(self.id, MESSAGE_TYPE.GROUP_LIST, response.encode())

        return self.encrypt_msg(msg_out)

    def handle_details(self, message):
        """
        Handle a request to retrieve details of a specific file.
        """
        content = message.get_content_object()
        assert isinstance(content, Details)
        
        file_id_to_read = content.file_id
        log.info("A details request was issued", f"{ message.sender} wants the details of the file {file_id_to_read}")

        file : File = files.get(content.file_id)
        
        if file is None:
            msg_out = self.trigger_alert("File does not exist",
                                         f"File {file_id_to_read} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        # go through the permissions of the users of the groups
        group_perms = {}
        for group_id in file.group_permissions:
            group = groups.get(group_id)
            if not group:
                msg_out = self.trigger_alert("Group does not exist",
                                             f"Group {group_id} does not exist",
                                             MESSAGE_TYPE.ERROR)
                return self.encrypt_msg(msg_out)
            
            user_perms = {}
            for user, perm in group.user_permissions.items():
                user_perms[user] = perm.name
            group_perms[str(group.ID)] = user_perms

        response = Details(
            file_id=file.ID,
            name=file.name,
            owner=file.owner,
            user_permissions=file.user_permissions,
            group_permissions=group_perms
        )
        msg_out = Message(self.id, MESSAGE_TYPE.DETAILS, response.encode())

        return self.encrypt_msg(msg_out)

    def handle_group_delete_user(self, message):
        """
        Handle a request to remove a user from a group.
        """
        content = message.get_content_object()
        assert isinstance(content, GroupDeleteUser)

        group_id = content.group_id
        user_id = content.user_id

        group = groups.get(group_id)
        user = users.get(user_id)

        if group is None:
            msg_out = self.trigger_alert("Group does not exist",
                                         f"Group {group_id} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if user is None:
            msg_out = self.trigger_alert("User does not exist",
                                         f"User {user_id} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if group.owner != message.sender:
            msg_out = self.trigger_alert("Sender is not the group's owner",
                                         f"{message.sender} is not the owner of group {group_id}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)
        
        if user_id == group.owner:
            msg_out = self.trigger_alert("Owner can't be removed from the group",
                                         f"{user_id} is the owner of group {group_id} and can't be removed",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if user_id not in group.users and group_id not in user.groups:
            msg_out = self.trigger_alert("User is not a group's member",
                                         f"{user_id} is not in group {group_id}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        group.users.remove(user_id)
        user.groups.remove(group_id)

        msg_out = self.trigger_alert("User was removed from the group",
                                     f"User {user_id} was removed from group {group_id}",
                                     MESSAGE_TYPE.SUCCESS)
        return self.encrypt_msg(msg_out)

    def handle_group_add_user(self, message):
        """
        Handle a request to add a user to a group with specific permissions.
        """
        content = message.get_content_object()
        assert isinstance(content, GroupAddUser)

        group_id = content.group_id
        user_id = content.user_id
        permissions = content.permissions
        file_nonce_key_list = content.file_nonce_key_list

        if permissions == PERMISSION.ERROR:
            msg_out = self.trigger_alert("Invalid permission type",
                                         f"{message.sender} used an invalid permission type",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        group = groups.get(group_id)
        user = users.get(user_id)

        if group is None:
            msg_out = self.trigger_alert("Group does not exist",
                                         f"Group {group_id} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if user is None:
            msg_out = self.trigger_alert("User does not exist",
                                         f"User {user_id} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if group.owner != message.sender:
            msg_out = self.trigger_alert("Sender is not the group's owner",
                                         f"{message.sender} is not the owner of group {group_id}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if user_id in group.users and group_id in user.groups:
            msg_out = self.trigger_alert("User is already a group's member",
                                         f"{user_id} is already in group {group_id}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)
        
        # first message from the client
        if file_nonce_key_list is None:
            other_file_nonce_key_dict = {}

            for file_id, file in files.items():
                if group_id in file.group_permissions:
                    nonce_key = file.keys.get(message.sender)
                    if nonce_key is not None:
                        other_file_nonce_key_dict[str(file_id)] = nonce_key


            user_pub_key_bytes = pubkey_bytes(user.cert.public_key())

            response = GroupAddUser(
                group_id=group_id,
                user_id=user_id,
                permissions=permissions,
                other_pub_key=user_pub_key_bytes,
                file_nonce_key_list=other_file_nonce_key_dict
            )

            msg_out = Message(
                self.id, MESSAGE_TYPE.GROUP_ADD_USER, response.encode())

            return self.encrypt_msg(msg_out)

            
        # second message from the client
        else:
            group.users.append(user_id)
            group.user_permissions[user_id] = permissions
            user.groups.append(group_id)

            for file_id, nonce_key in file_nonce_key_list.items():
                file = files.get(int(file_id))
                if file is None:
                    msg_out = self.trigger_alert("File does not exist",
                                                 f"File {file_id} does not exist",
                                                 MESSAGE_TYPE.ERROR)
                    return self.encrypt_msg(msg_out)

                file.keys[user_id] = nonce_key

            msg_out = self.trigger_alert("User was added to the group",
                                        f"User {user_id} was added to group {group_id}",
                                        MESSAGE_TYPE.SUCCESS)
            return self.encrypt_msg(msg_out)

    def handle_group_add(self, message):
        """
        Handle a request to add a file to a group.
        """
        content = message.get_content_object()
        assert isinstance(content, GroupAdd)

        group_id = content.group_id
        file_path = content.file_path
        nonce_key_list = content.nonce_key_list
        
        group = groups.get(group_id)
        if group is None:
            msg_out = self.trigger_alert("Group does not exist",
                                         f"Group {group_id} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)
        
        user_perm = group.user_permissions.get(message.sender)
        if user_perm is None:
            msg_out = self.trigger_alert("Sender does not belong to group",
                                         f"User {message.sender} is not part of group {group_id}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if user_perm not in [PERMISSION.W, PERMISSION.RW]:
            msg_out = self.trigger_alert("Sender has no permission to add files",
                                         f"User {message.sender} has only {user_perm.name} permission in group {group_id}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        # first message from the client
        if nonce_key_list is None:
            
            other_pub_key_list = {}

            for user_id in group.users:
                user = users.get(user_id)
                if user is None:
                    msg_out = self.trigger_alert("User does not exist",
                                                 f"User {user_id} does not exist",
                                                 MESSAGE_TYPE.ERROR)
                    return self.encrypt_msg(msg_out)

                if group.user_permissions.get(user_id) in [PERMISSION.R, PERMISSION.RW]:
                    other_pub_key_list[user_id] = (pubkey_bytes(user.cert.public_key()))

            response = GroupAdd(
                group_id=group_id,
                file_path=file_path,
                nonce_key_list=None,
                other_pub_key_list=other_pub_key_list,
                file_content=None
            )

            msg_out = Message(
                self.id, MESSAGE_TYPE.GROUP_ADD, response.encode())

            return self.encrypt_msg(msg_out)

            
        # second message from the client
        else:
            file_name = os.path.basename(file_path)
            file_owner = message.sender

            group_permissions = [group_id]
            keys_dict = {}
            for user_id, nonce_key in nonce_key_list.items():
                user = users.get(user_id)
                if user is None:
                    msg_out = self.trigger_alert("User does not exist",
                                                 f"User {user_id} does not exist",
                                                 MESSAGE_TYPE.ERROR)
                    return self.encrypt_msg(msg_out)

                keys_dict[user_id] = nonce_key

            f = File(file_name, file_owner, content.file_content, {}, group_permissions, keys_dict)
            files[f.ID] = f

            msg_out = self.trigger_alert("File shared with group",
                                         f"File {file_name} (whose file ID is {f.ID}) was shared with group {group_id} by {message.sender}",
                                         MESSAGE_TYPE.SUCCESS)
            return self.encrypt_msg(msg_out)

    def handle_group_create(self, message):
        """
        Handle a request to create a new group.
        """
        content = message.get_content_object()
        assert isinstance(content, GroupCreate)

        group_name = content.name
        perms = {message.sender: PERMISSION.RW}
        group = Group(message.sender, group_name, [message.sender], perms)
        group_id = group.ID
        groups[group_id] = group

        user = users.get(message.sender)
        if user is None:
            msg_out = self.trigger_alert("User not registered",
                                         f"User {message.sender} not found for creating group",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)
        
        user.groups.append(group_id)
        users[message.sender] = user

        msg_out = self.trigger_alert(f"Group {group_name} was created by {message.sender} and has ID {group_id}",
                                     f"Group {group_name} was created by {message.sender} and has ID {group_id}",
                                     MESSAGE_TYPE.SUCCESS)
        return self.encrypt_msg(msg_out)

    def handle_group_delete(self, message):
        """
        Handle a request to delete a group.
        """
        content = message.get_content_object()
        assert isinstance(content, GroupDelete)

        group_id = content.group_id
        group = groups.get(group_id)
        if group is None:
            msg_out = self.trigger_alert("Group does not exist",
                                         f"Group {group_id} does not exist.",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if group.owner != message.sender:
            msg_out = self.trigger_alert("Permission denied",
                                         f"{message.sender} is not the owner of group {group_id}.",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        # remove from file permissions
        for file in files.values():
            if group_id in file.group_permissions:
                file.group_permissions.remove(group_id)

        # remove the group from users
        for user_id in group.users:
            user : User = users.get(user_id)
            if user and group_id in user.groups:
                user.groups.remove(group_id)

        # remove group from the group dictionary
        del groups[group_id]

        msg_out = self.trigger_alert("Group deleted",
                                     f"Group {group_id} deleted by {message.sender}.",
                                     MESSAGE_TYPE.SUCCESS)
        return self.encrypt_msg(msg_out)
    
    def handle_group_details(self, message):
        """
        Handle a request to retrieve details of a specific group.
        """
        content = message.get_content_object()
        assert isinstance(content, GroupDetails)

        group_id = content.group_ID
        group = groups.get(group_id)

        log.info("A group details request was issued", f"{message.sender} wants the details of group {group_id}")

        if group is None:
            msg_out = self.trigger_alert("Group does not exist",
                                         f"Group {group_id} does not exist.",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        response = GroupDetails(
            group_ID=group.ID,
            group_name=group.name,
            group_owner=group.owner,
            group_permissions=group.user_permissions
        )
        msg_out = Message(self.id, MESSAGE_TYPE.GROUP_DETAILS, response.encode())

        return self.encrypt_msg(msg_out)

    def handle_delete(self, message):
        """
        Handle a request to delete a file from the server.
        """
        content = message.get_content_object()
        assert isinstance(content, Delete)

        file_id_to_delete = content.file_id

        file = files.get(file_id_to_delete)
        if file is None:
            msg_out = self.trigger_alert("File does not exist",
                                         f"File {file_id_to_delete} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        sender_permissions = file.user_permissions.get(message.sender)

        if sender_permissions is None or sender_permissions == PERMISSION.R:
            msg_out = self.trigger_alert("Sender does not have access to file",
                                         f"{message.sender} does not have delete access to file {file_id_to_delete}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        # file owner deletes file for everyone
        if file.owner == message.sender:
            files.pop(file_id_to_delete)
            msg_out = self.trigger_alert("File deleted",
                                         f"File {file.name} (whose file ID is {file.ID}) was deleted for everyone, prompted by file owner {message.sender}",
                                         MESSAGE_TYPE.SUCCESS)
            return self.encrypt_msg(msg_out)
        # file that's been shared is only deleted to that person
        else:
            file.user_permissions.pop(message.sender)
            msg_out = self.trigger_alert("File deleted",
                                         f"File {file.name} (whose file ID is {file.ID}) was deleted for sender only, prompted by {message.sender}",
                                         MESSAGE_TYPE.SUCCESS)
            return self.encrypt_msg(msg_out)

    def handle_revoke(self, message):
        """
        Handle a request to revoke a user's access to a file.
        """
        content = message.get_content_object()
        assert isinstance(content, Revoke)

        file_id_to_revoke = content.file_id
        user_id_to_revoke = content.user_id

        file = files.get(file_id_to_revoke)
        if file is None:
            msg_out = self.trigger_alert("File does not exist",
                                         f"File {file_id_to_revoke} does not exist",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if file.owner != message.sender:
            msg_out = self.trigger_alert("Sender does not have access to file",
                                         f"{message.sender} does not have revoke access to file {file_id_to_revoke}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        if file.owner == user_id_to_revoke:
            msg_out = self.trigger_alert("File owner can't revoke himself",
                                         f"{file.owner}, owner of file {file_id_to_revoke}, can not revoke access to himself",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        popped_user = file.user_permissions.pop(user_id_to_revoke, None)
        if popped_user is None:
            msg_out = self.trigger_alert("User does not have access to file",
                                         f"{user_id_to_revoke} does not have access to file {file.ID}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        msg_out = self.trigger_alert("Revoke request was issued",
                                     f"Revoked {user_id_to_revoke}'s access to file {file.ID}, prompted by file owner {message.sender}",
                                     MESSAGE_TYPE.SUCCESS)
        return self.encrypt_msg(msg_out)
    
    def process(self, msg):
        """
        Process an incoming message from the client, decrypt it, and route it to the appropriate handler.
        """
        self.msg_cnt += 1

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(self.shared)

        aesgcm = AESGCM(derived_key)

        struct_msg, nonce = (msg[:-12], msg[-12:])
        try:
            struct_msg = aesgcm.decrypt(nonce, struct_msg, None)
        except Exception as e:
            msg_out = self.trigger_alert("Failed to decrypt message",
                                         f"Decryption error: {e}",
                                         MESSAGE_TYPE.ERROR)
            return self.encrypt_msg(msg_out)

        return self.handleMessage(struct_msg)


async def handle_echo(reader, writer):
    """
    Handle a client connection, perform a handshake, and process messages in a loop.
    """
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(addr)

    async def shutdown_connection():
        """Helper to close the current connection gracefully."""
        log.info("Shutting down connection", f"Closing connection with {addr}")
        try:
            writer.close()
            await writer.wait_closed()
            log.success("Connection closed", f"Connection with {addr} has been successfully closed")
        except Exception as e:
            log.error("Error during connection shutdown", f"{addr}: {e}")

    try:
        # --- load keystore and certificates ---
        private_key, server_cert, _ = get_userdata("p12/" + keystore_filepath, password)
        if private_key is None or server_cert is None:
            log.error("Missing private key or user certificate", "Missing private key or user certificate")
            await shutdown_connection()
            return
        
        # validate server certificate
        if not validate_cert(CA_cert, server_cert, "vault_sv"):
            log.error("Invalid server certificate", "The server's certificate is invalid")
            await shutdown_connection()
            return

        # set up server worker
        srvwrk.set_RSA_priv_key(private_key)
        srvwrk.set_sv_cert(server_cert)
        srvwrk.set_sv_id()

        # generate and serialize our public key
        sv_pubkey = srvwrk.getPublic()
        sv_pubkey_bytes = pubkey_bytes(sv_pubkey)
        if sv_pubkey_bytes is None:
            log.error("Unable to serialize public key", "The public key could not be serialized into bytes")
            await shutdown_connection()
            return

        # --- handshake: receive client's pubkey ---
        cli_pubkey = await reader.read(max_msg_size)

        # sign and send (PUBKs + PUBKc) + CERTs
        sv_sig = srvwrk.sign(sv_pubkey_bytes + cli_pubkey)
        if sv_sig is None:
            log.error("Unable to sign public key", "The public key could not be signed")
            await shutdown_connection()
            return

        sv_cert_bytes = cert_to_bytes(srvwrk.sv_cert)
        writer.write(couple(sv_pubkey_bytes, sv_sig, sv_cert_bytes))
        await writer.drain()

        # receive client's signature and certificate
        data = await reader.read(max_msg_size)
        if not data or data.startswith(b'\n'):
            log.info("Connection closed", f"Connection closed by {addr}")
            await shutdown_connection()
            return

        cli_sig, cli_cert_bytes = unpair(data)
        cli_cert = bytes_to_cert(cli_cert_bytes)

        # validate client certificate
        if not validate_cert(CA_cert, cli_cert, None):
            log.error("Invalid client certificate", "The client's certificate is invalid")
            await shutdown_connection()
            return

        # extract and verify client's pubkey and signature
        RSA_cli_pubkey = cli_cert.public_key()
        if not isinstance(RSA_cli_pubkey, rsa.RSAPublicKey):
            log.error("Invalid public key type", "The public key type is not valid")
            await shutdown_connection()
            return

        message = cli_pubkey + sv_pubkey_bytes
        if not validate_signature(RSA_cli_pubkey, cli_sig, message):
            log.error("Invalid signature", "The signature is invalid")
            await shutdown_connection()
            return

        # register or welcome-back the user
        cli_id_attr = cli_cert.subject.get_attributes_for_oid(NameOID.PSEUDONYM)
        cli_id = cli_id_attr[0].value if cli_id_attr else "unknown"
        common_name_attr = cli_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cli_name = common_name_attr[0].value if common_name_attr else cli_id

        if (cli_id not in users) or (users[cli_id].cert != cli_cert):
            users[cli_id] = User(ID=cli_id, name=cli_name,
                                 groups=[], cert=cli_cert)
            log.info("New user registered", f"New user '{cli_id}' registered")
        else:
            log.info("Known user joined", f"User '{cli_id}' is already known")

        # generate shared key
        srvwrk.generateShared(cli_pubkey)

        # --- main echo loop ---
        while True:
            data = await reader.read(max_msg_size)
            if not data or data.startswith(b'\n'):
                log.info("Connection closed", f"Connection closed by {addr}")
                break

            response = srvwrk.process(data)
            if response:
                writer.write(response)
                await writer.drain()

    except Exception as e:
        # catch-all for any unexpected error during handling
        log.error(f"Communication error with {addr}: {e}", f"Communication error with {addr}: {e}")

    finally:
        # ensure the connection is always cleaned up
        await shutdown_connection()



def run_server(new_dataset):
    """
    Start the server, optionally with a new dataset, and handle incoming connections.
    """
    if not new_dataset:
        load_from_db()
    else: 
        log.info("New dataset", "Starting with a new dataset")

    if not os.path.exists("p12/" + keystore_filepath):
        log.warn("Keystore not found", f"Keystore file {keystore_filepath} not found")
        create_account(keystore_filepath[:-4], password)
        log.success("Keystore created", f"Keystore file created at p12/{keystore_filepath}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    log.info("Server is running", 'Serving on {}'.format(
        server.sockets[0].getsockname()))
    log.info('  (type ^C to finish)', '  (type ^C to finish)')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        save_to_db()
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()
        log.success('Finished!', 'Finished!')

parser = argparse.ArgumentParser(description="Server argument parser")

# flag -p / --printlog: prints logs to the console
parser.add_argument(
    "-p", "--printlog",
    action="store_true",
    default=False,
    help="Print logs to the console (default: False)"
)

# flag -l / --loglevel: determines the verbosity of the logs
parser.add_argument(
    "-l", "--loglevel",
    type=int,
    choices=[0, 1],
    default=0,
    help="Set log level: 0 = INFO, 1 = VERBOSE (default: 0)"
)

# flag -n / --new: starts the server with a new dataset
parser.add_argument(
    "-n", "--new",
    action="store_true",
    default=False,
    help="Start the server with a new dataset (default: False)"
)

args = parser.parse_args()

log = Logger(file_path="logs/log.txt",
             show_output=args.printlog, level=args.loglevel)

log.info("Server is running on INFO mode",
         "Server is running on VERBOSE mode")

run_server(new_dataset=args.new)
