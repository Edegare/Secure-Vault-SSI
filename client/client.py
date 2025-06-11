import asyncio
import os
import sys
import readline
import shlex

from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.completion import WordCompleter

from entities.permission_enum import PERMISSION
from utils.key_utils import pubkey_bytes
from utils.cert_utils import bytes_to_cert, cert_to_bytes, validate_cert, validate_signature, sign, cert_load
from utils.utils import decouple, mkpair, pretty_print_message
from utils.ui import login_ui

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

from entities.permission_enum import PERMISSION

conn_port = 7777
max_msg_size = 9999

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

CA_cert = cert_load("crt/ca.crt")

command_completer = WordCompleter(
    words=[
        "add",
        "delete",
        "revoke",
        "read",
        "list",
        "details",
        "replace",
        "share",
        "group",
        "group list",
        "group delete",
        "group details",
        "group create",
        "group add",
        "group add-user",
        "group delete-user",
        "help",
        "exit",
        "clear",
    ],
    sentence=True,
    ignore_case=True,
)

command_session = PromptSession(
    completer=command_completer,
    complete_style=CompleteStyle.READLINE_LIKE,
)


class Client:
    """ Class that implements the functionality of a CLIENT. """

    def __init__(self, r: asyncio.StreamReader, w: asyncio.StreamWriter, sckt=None):
        """Initializes the Client instance."""
        self.sckt = sckt
        self.msg_cnt = 0
        self.r = r
        self.w = w

    def set_RSA_priv_key(self, RSA_priv_key):
        """Sets the RSA private key for the client."""
        if RSA_priv_key is None:
            raise ValueError("RSA private key cannot be None")
        self.RSA_priv_key = RSA_priv_key

    def set_cli_cert(self, cli_cert):
        """Sets the client certificate."""
        if cli_cert is None:
            raise ValueError("Client certificate cannot be None")
        self.cli_cert = cli_cert

    def load_public_key(self):
        """Loads the public key from the client certificate."""
        if not hasattr(self, 'cli_cert'):
            raise AttributeError("Client certificate is not set. Cannot load public key.")
        self.RSA_pub_key = self.cli_cert.public_key()

    def set_cli_id(self):
        """Sets the client ID based on the pseudonym attribute in the client certificate."""
        if not hasattr(self, 'cli_cert'):
            raise AttributeError("Client certificate is not set. Cannot set client ID.")
        nameAttribute = self.cli_cert.subject.get_attributes_for_oid(NameOID.PSEUDONYM)
        if not nameAttribute:
            raise ValueError("Pseudonym attribute not found in client certificate")
        assert len(nameAttribute) == 1
        self.id = nameAttribute.pop().value

    def sign(self, message):
        """Signs a message using the client's RSA private key."""
        return sign(self.RSA_priv_key, message)

    def getPublic(self):
        """Generates and returns the client's Diffie-Hellman public key."""
        pn = dh.DHParameterNumbers(p, g)
        self.private = pn.parameters().generate_private_key()
        self.public = self.private.public_key()
        return self.public

    def generateShared(self, public):
        """Generates a shared key using the provided public key."""
        if public is None:
            raise ValueError("Public key cannot be None")
        try:
            publicKey = load_pem_public_key(public)
            if not isinstance(publicKey, dh.DHPublicKey):
                raise TypeError("Provided public key is not a valid DH public key")
            self.shared = self.private.exchange(publicKey)
        except Exception as e:
            raise RuntimeError(f"Failed to generate shared key: {e}")

    async def sendMsg(self, msg: Message):
        """Encrypts and sends a message to the server."""
        if not hasattr(self, 'shared'):
            raise AttributeError("Shared key is not set. Cannot send message.")
        if not isinstance(msg, Message):
            raise TypeError("Provided message is not of type Message")
        derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
        ).derive(self.shared)

        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, msg.encode(), None) + nonce
        self.w.write(ct) 
        await self.w.drain()
        self.msg_cnt += 1

    async def processMsg(self, msg) -> int:
        """Processes a received message from the server."""
        m = Message.decode(msg)
        msg_type = m.header
        content = m.get_content_object()

        if msg_type == MESSAGE_TYPE.READ:
            await self.handle_read(content)
        elif msg_type == MESSAGE_TYPE.SHARE:
            await self.handle_share(content)
        elif msg_type == MESSAGE_TYPE.REPLACE:
            await self.handle_replace(content)
        elif msg_type == MESSAGE_TYPE.LIST:
            self.handle_list(content)
        elif msg_type == MESSAGE_TYPE.GROUP_LIST:
            self.handle_group_list(content)
        elif msg_type == MESSAGE_TYPE.DETAILS:
            self.handle_details(content)
        elif msg_type == MESSAGE_TYPE.GROUP_ADD:
            await self.handle_group_add(content)
        elif msg_type == MESSAGE_TYPE.GROUP_ADD_USER:
            await self.handle_group_add_user(content)
        elif msg_type == MESSAGE_TYPE.GROUP_DETAILS:
            self.handle_group_details(content)
        elif msg_type == MESSAGE_TYPE.SUCCESS:
            self.handle_success(content)
        elif msg_type == MESSAGE_TYPE.ERROR:
            self.handle_error(content)

    async def handle_read(self, content: Read):
        """Handles a READ message from the server."""
        assert isinstance(content, Read)

        if content.file is None:
            raise Warning("File content cannot be None")

        if not content.file_name:
            raise Warning("File name is missing")

        print(f"file name: {content.file_name}")

        # decode file content
        nonce_key = self.RSA_priv_key.decrypt(
            content.nonce_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        nonce = nonce_key[:12]
        key = nonce_key[12:]

        aesgcm = AESGCM(key)
        file_content = aesgcm.decrypt(nonce, content.file, None)

        pretty_print_message(file_content.decode('utf-8'))

    async def handle_share(self, content: Share):
        """Handles a SHARE message from the server."""
        assert isinstance(content, Share)

        if content.other_pub_key is None and content.nonce_key is None:
            raise Warning("Empty content")

        # decrypt file content
        nonce_key = self.RSA_priv_key.decrypt(
            content.nonce_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        nonce = nonce_key[:12]
        key = nonce_key[12:]

        # load public key
        public_key = load_pem_public_key(content.other_pub_key)

        # encrypt nonce + key with the other client's key
        encrypted_nonce_key = public_key.encrypt(
            nonce + key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # create new message
        new_msg = Share(
            file_id=int(content.file_id),
            user_id=content.user_id,
            permission=content.permission,
            nonce_key=encrypted_nonce_key,
            other_pub_key=None
        )

        enc_msg = Message(self.id, MESSAGE_TYPE.SHARE, new_msg.encode())
        await self.sendMsg(enc_msg)

    def handle_list(self, content: List):
        """Handles a LIST message from the server."""
        assert isinstance(content, List)

        if content.availableFiles is None:
            raise Warning("No files available in the list")

        print(f"Available files:")
        for user_id, file_id, file_name, file_permissions in content.availableFiles:
            print(f"    User ID: {user_id}, File ID: {file_id}, File Name: {file_name}, Permissions: {file_permissions}")

    def handle_group_list(self, content: GroupList):
        """Handles a GROUP_LIST message from the server."""
        assert isinstance(content, GroupList)

        if not content.groups:
            print("You are not a member of any group.")
        else:
            print("Groups you belong to:")
            for group_id, group_name, permission in content.groups:
                print(f"  - Group ID: {group_id}, Name: {group_name}, Permission: {permission}")

    def handle_details(self, content: Details):
        """Handles a DETAILS message from the server."""
        assert isinstance(content, Details)

        print(f"== Details of File {content.file_id} ==")
        print(f"Name: {content.name}")
        print(f"Owner: {content.owner}")

        if content.user_permissions:
            print("Individual Permissions:")
            for user, perm in content.user_permissions.items():
                print(f"  - {user}: {perm}")
        else:
            print("No individual permissions.")

        if content.group_permissions:
            print("Group Permissions:")
            for group, users in content.group_permissions.items():
                print(f"  Group {group}:")
                for user, perm in users.items():
                    print(f"    - {user}: {perm}")
        else:
            print("No group permissions.")

    async def handle_replace(self, content: Replace):
        """Handles a REPLACE message from the server."""
        assert isinstance(content, Replace)

        if not os.path.exists(content.file_path):
            raise Warning(f"File path does not exist: {content.file_path}")

        if not content.other_pub_key_list:
            raise Warning("Public key list is missing for group replace")

        file_path = content.file_path
        file = open(file_path, "rb").read()

        key = AESGCM.generate_key(128)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_file = aesgcm.encrypt(nonce, file, None)

        nonce_key_list = {}

        for user_id, pub_key in content.other_pub_key_list.items():
            public_key = load_pem_public_key(pub_key)

            encrypted_nonce_key = public_key.encrypt(
                nonce + key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            nonce_key_list[user_id] = encrypted_nonce_key

        # create new message
        response = Replace(
            id_to_replace=content.id_to_replace,
            file_path=file_path,
            nonce_key_list=nonce_key_list,
            other_pub_key_list=None,
            file_content=encrypted_file
        )

        enc_msg = Message(self.id, MESSAGE_TYPE.REPLACE, response.encode())
        await self.sendMsg(enc_msg)

        # receive and handle the final alert from the server
        last_msg = await self.r.read(max_msg_size)
        if not last_msg:
            print("\033[93m[WARN] No response from server.\033[0m")
            return 0

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(self.shared)

        aesgcm = AESGCM(derived_key)
        last_msg, nonce = last_msg[:-12], last_msg[-12:]
        decrypted = aesgcm.decrypt(nonce, last_msg, None)
        m = Message.decode(decrypted)
        content = m.get_content_object()
        if not isinstance(content, Alert):
            raise Warning("Expected Alert content type")
        if m.header == MESSAGE_TYPE.SUCCESS:
            print(f"\033[92m[SUCCESS] {content.message}\033[0m")
        elif m.header == MESSAGE_TYPE.ERROR:
            print(f"\033[91m[ERROR] {content.message}\033[0m")
        else:
            raise Warning("Unexpected message type")


    async def handle_group_add(self, content: GroupAdd):
        """Handles a GROUP_ADD message from the server."""
        assert isinstance(content, GroupAdd)

        if not os.path.exists(content.file_path):
            raise Warning(f"File path does not exist: {content.file_path}")

        if not content.other_pub_key_list:
            raise Warning("Public key list is missing for group add")

        file_path = content.file_path
        file = open(file_path, "rb").read()

        key = AESGCM.generate_key(128)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_file = aesgcm.encrypt(nonce, file, None)

        nonce_key_list = {}

        for user_id, pub_key in content.other_pub_key_list.items():
            public_key = load_pem_public_key(pub_key)

            encrypted_nonce_key = public_key.encrypt(
                nonce + key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            nonce_key_list[user_id] = encrypted_nonce_key

        # create new message
        response = GroupAdd(
            group_id=content.group_id,
            file_path=file_path,
            nonce_key_list=nonce_key_list,
            other_pub_key_list=None,
            file_content=encrypted_file
        )

        enc_msg = Message(self.id, MESSAGE_TYPE.GROUP_ADD, response.encode())
        await self.sendMsg(enc_msg)

        # receive and handle the final alert from the server
        last_msg = await self.r.read(max_msg_size)
        if not last_msg:
            print("\033[93m[WARN] No response from server.\033[0m")
            return 0

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(self.shared)

        aesgcm = AESGCM(derived_key)
        last_msg, nonce = last_msg[:-12], last_msg[-12:]
        decrypted = aesgcm.decrypt(nonce, last_msg, None)
        m = Message.decode(decrypted)
        content = m.get_content_object()
        if not isinstance(content, Alert):
            raise Warning("Expected Alert content type")
        if m.header == MESSAGE_TYPE.SUCCESS:
            print(f"\033[92m[SUCCESS] {content.message}\033[0m")
        elif m.header == MESSAGE_TYPE.ERROR:
            print(f"\033[91m[ERROR] {content.message}\033[0m")
        else:
            raise Warning("Unexpected message type")
        
    async def handle_group_add_user(self, content: GroupAddUser):
        """Handles a GROUP ADD USER message from the server."""
        assert isinstance(content, GroupAddUser)

        if content.file_nonce_key_list is None:
            return
        
        other_RSA_pub_key = load_pem_public_key(content.other_pub_key)
        other_file_nonce_key_dict = {}

        for file_id, encrypted_nonce_key in content.file_nonce_key_list.items():
            # decrypt only the nonce_key
            nonce_key = self.RSA_priv_key.decrypt(
                encrypted_nonce_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            nonce = nonce_key[:12]
            key = nonce_key[12:]


            # encrypt the nonce + key with the other client's key
            other_file_nonce_key_dict[file_id] = other_RSA_pub_key.encrypt(
                nonce + key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

        # create new message
        response = GroupAddUser(
            group_id=content.group_id,
            user_id=content.user_id,
            permissions=content.permissions,
            other_pub_key=None,
            file_nonce_key_list=other_file_nonce_key_dict
        )

        enc_msg = Message(self.id, MESSAGE_TYPE.GROUP_ADD_USER, response.encode())
        await self.sendMsg(enc_msg)

        # receive and handle the final alert from the server
        last_msg = await self.r.read(max_msg_size)
        if not last_msg:
            print("\033[93m[WARN] No response from server.\033[0m")
            return 0

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(self.shared)

        aesgcm = AESGCM(derived_key)
        last_msg, nonce = last_msg[:-12], last_msg[-12:]
        decrypted = aesgcm.decrypt(nonce, last_msg, None)
        m = Message.decode(decrypted)
        content = m.get_content_object()
        if not isinstance(content, Alert):
            raise Warning("Expected Alert content type")
        if m.header == MESSAGE_TYPE.SUCCESS:
            print(f"\033[92m[SUCCESS] while processing server response: {content.message}\033[0m")
        elif m.header == MESSAGE_TYPE.ERROR:
            print(f"\033[91m[ERROR] while processing server response: {content.message}\033[0m")
        else:
            raise Warning("Unexpected message type")
        
    def handle_group_details(self, content: GroupDetails):
        """Handles a GROUP DETAILS message from the server."""
        assert isinstance(content, GroupDetails)

        print(f"== Details of Group {content.group_ID} ==")
        print(f"Group name: {content.group_name}")
        print(f"Group owner: {content.group_owner}")

        if content.group_permissions:
            print("Group Permissions:")
            for user_id, permission in content.group_permissions:
                print(f"  - {user_id}: {permission}")
        else:
            print("No group permissions.")

    def handle_success(self, content: Alert):
        """Handles a SUCCESS message from the server."""
        assert isinstance(content, Alert)

        success_message = content.message
        print(f"\033[92m[SUCCESS] message from server: {success_message}\033[0m")

    def handle_error(self, content: Alert):
        """Handles an ERROR message from the server."""
        assert isinstance(content, Alert)

        error_message = content.message
        print(f"\033[91m[ERROR] message form server: {error_message}\033[0m")

    async def processCommand(self) -> int:
        """Processes a command entered by the user."""
        raw = await command_session.prompt_async(f"({self.id}) >> ")
        readline.add_history(raw)
        try:
            # to handle quoted strings
            command = shlex.split(raw)
        except ValueError as e:
            print(f"\033[91m[ERROR] Invalid input: {e}\033[0m")
            return 1
        
        if not command:
            print("No command entered.")
            return 1
        command_type = command[0].lower()
        status = 1

        if command_type == "exit":
            print("Exiting...")
            return 0

        try:
            msg = None

            if command_type == "add":
                if len(command) != 2:
                    print("Usage: add <file_path>")
                    return 1

                msg = self._handle_add(command)
                status = 2
            elif command_type == "delete":
                if len(command) != 2 or not command[1].isdigit():
                    print("Usage: delete <file_id>")
                    return 1

                msg = self._handle_delete(command)
                status = 2
            elif command_type == "revoke":
                if len(command) != 3:
                    print("Usage: revoke <file_id> <user_id>")
                    return 1

                msg = self._handle_revoke(command)
                status = 2
            elif command_type == "read":
                if len(command) != 2 or not command[1].isdigit():
                    print("Usage: read <file_id>")
                    return 1

                msg = self._handle_read(command)
                status = 2
            elif command_type == "list":
                if len(command) != 3 or command[1] not in ["-u", "-g"]:
                    print("Usage: list [-u user_id | -g group_id]")
                    return 1

                msg = self._handle_list(command)
                status = 2
            elif command_type == "details":
                if len(command) != 2 or not command[1].isdigit():
                    print("Usage: details <file_id>")
                    return 1

                msg = self._handle_details(command)
                status = 2
            elif command_type == "replace":
                if len(command) != 3:
                    print("Usage: replace <file_id> <file_path>")
                    return 1

                msg = self._handle_replace(command)
                status = 2
            elif command_type == "share":
                if len(command) != 4 or command[3].upper() not in ["R", "W", "RW"]:
                    print("Usage: share <file_id> <user_id> <permission (R|W|RW)>")
                    return 1

                msg = self._handle_share(command)
                status = 2
            elif command_type.startswith("group"):
                # handle group-related commands
                msg, status = self._handle_group_commands(command)
            elif command_type == "help":
                print("Available commands:")
                print("  add <file_path>")
                print("  delete <file_id>")
                print("  revoke <file_id> <user_id>")
                print("  read <file_id>")
                print("  list [-u user_id | -g group_id]")
                print("  details <file_id>")
                print("  replace <file_id> <file_path>")
                print("  share <file_id> <user_id> <permission (R|W|RW)>")
                print("  group list")
                print("  group delete <group_id>")
                print("  group details <group_id>")
                print("  group create <group_name>")
                print("  group add <group_id> <file_path>")
                print("  group add-user <group-id> <user-id> <permission (R|W|RW)>")
                print("  group delete-user <group-id> <user-id>")
                print("  help")
                print("  clear")
                print("  exit")
            elif command_type == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
            else:
                print(f"Unknown command: use 'help' for a list of commands.")
                return 1

            if msg:
                await self.sendMsg(msg)
        except Exception as e:
            print(f"\033[91m[ERROR] message from client: {e}\033[0m")

        return status

    def _handle_add(self, command):
        """Handles the ADD command."""
        file_path = command[1]
        file_name = os.path.basename(file_path)
        file_owner = self.id
        file = open(file_path, "rb").read()

        key, nonce, encrypted_file = self._encrypt_file(file)
        encrypted_nonce_key = self._encrypt_nonce_key(nonce, key)

        return Message(self.id, MESSAGE_TYPE.ADD, Add(file_name, file_owner, encrypted_file, encrypted_nonce_key).encode())

    def _handle_delete(self, command):
        """Handles the DELETE command."""
        file_id = int(command[1])
        return Message(self.id, MESSAGE_TYPE.DELETE, Delete(file_id).encode())

    def _handle_revoke(self, command):
        """Handles the REVOKE command."""
        file_id = command[1]
        user_id = command[2]
        return Message(self.id, MESSAGE_TYPE.REVOKE, Revoke(int(file_id), user_id).encode())

    def _handle_read(self, command):
        """Handles the READ command."""
        file_id = int(command[1])
        return Message(self.id, MESSAGE_TYPE.READ, Read(file_id, None, None, None).encode())

    def _handle_list(self, command):
        """Handles the LIST command."""
        flag = command[1]
        id = command[2]
        is_user = (flag == "-u")
        return Message(self.id, MESSAGE_TYPE.LIST, List(id, is_user, None).encode())

    def _handle_details(self, command):
        """Handles the DETAILS command."""
        file_id = int(command[1])
        return Message(self.id, MESSAGE_TYPE.DETAILS, Details(file_id).encode())

    def _handle_replace(self, command):
        """Handles the REPLACE command."""
        id_to_replace = command[1]
        file_path = command[2]

        return Message(self.id, MESSAGE_TYPE.REPLACE, Replace(int(id_to_replace), file_path, None, None, None).encode())

    def _handle_share(self, command):
        """Handles the SHARE command."""
        file_id = command[1]
        user_id = command[2]
        permission = command[3].upper()

        if permission not in ["R", "W", "RW"]:
            raise Warning("Invalid permission. Use R, W, or RW.")

        return Message(self.id, MESSAGE_TYPE.SHARE, Share(int(file_id), user_id, PERMISSION[permission], None, None).encode())

    def _handle_group_commands(self, command):
        """Handles group-related commands."""
        group_command = command[1]
        status = 1

        if group_command == "list":
            if len(command) != 2:
                print("Usage: group list")
                return None, 1

            content = GroupList()
            msg = Message(self.id, MESSAGE_TYPE.GROUP_LIST, content.encode())
            status = 2
        elif group_command == "delete":
            if len(command) != 3 or not command[2].isdigit():
                print("Usage: group delete <group_id>")
                return None, 1

            group_id = command[2]
            content = GroupDelete(int(group_id))
            msg = Message(self.id, MESSAGE_TYPE.GROUP_DELETE, content.encode())
            status = 2
        elif group_command == "details":
            if len(command) != 3 or not command[2].isdigit():
                print("Usage: group details <group_id>>")
                return None, 1

            group_id = command[2]
            content = GroupDetails(int(group_id), None, None, None)
            msg = Message(self.id, MESSAGE_TYPE.GROUP_DETAILS, content.encode())
            status = 2
        elif group_command == "create":
            if len(command) != 3:
                print("Usage: group create <group_name>")
                return None, 1

            group_name = command[2]
            msg = Message(self.id, MESSAGE_TYPE.GROUP_CREATE, GroupCreate(group_name, None).encode())
            status = 2
        elif group_command == "add":
            if len(command) != 4 or not command[2].isdigit():
                print("Usage: group add <group_id> <file_path>")
                return None, 1

            group_id = command[2]
            file_path = command[3]
            msg = Message(self.id, MESSAGE_TYPE.GROUP_ADD, GroupAdd(int(group_id), file_path, None, None, None).encode())
            status = 2
        elif group_command == "add-user":
            if len(command) != 5 or not command[2].isdigit() or command[4].upper() not in ["R", "W", "RW"]:
                print("Usage: group add-user <group-id> <user-id> <permission (R|W|RW)>")
                return None, 1

            group_id = command[2]
            user_id = command[3]
            permissions = self._parse_permissions(command[4])
            content = GroupAddUser(int(group_id), user_id, permissions, None, None)
            msg = Message(self.id, MESSAGE_TYPE.GROUP_ADD_USER, content.encode())
            status = 2
        elif group_command == "delete-user":
            if len(command) != 4 or not command[2].isdigit():
                print("Usage: group delete-user <group-id> <user-id>")
                return None, 1

            group_id = command[2]
            user_id = command[3]
            msg = Message(self.id, MESSAGE_TYPE.GROUP_DELETE_USER, GroupDeleteUser(int(group_id), user_id).encode())
            status = 2
        else:
            raise Warning("Invalid group command.")

        return msg, status

    def _encrypt_file(self, file):
        """Encrypts a file using AES-GCM."""
        if not file:
            raise Warning("File content cannot be empty")
        key = AESGCM.generate_key(128)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_file = aesgcm.encrypt(nonce, file, None)
        return key, nonce, encrypted_file

    def _encrypt_nonce_key(self, nonce, key):
        """Encrypts the nonce and key using the client's RSA public key."""
        if nonce is None or key is None:
            raise Warning("Nonce or key cannot be None")
        return self.RSA_pub_key.encrypt(
            nonce + key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def _parse_permissions(self, permissions):
        """Parses the permissions string into a PERMISSION enum."""
        if not permissions:
            raise Warning("Permissions cannot be empty")
        permissions = permissions.lower()
        if permissions == "r":
            return PERMISSION.R
        elif permissions in ["rw", "wr"]:
            return PERMISSION.RW
        elif permissions == "w":
            return PERMISSION.W
        else:
            return PERMISSION.ERROR

    async def process(self) -> int:
        """Processes messages and commands in a loop."""
        if not hasattr(self, 'shared'):
            raise Warning("Shared key is not set. Cannot process messages.")
        status = await self.processCommand()

        if status == 2:
            try:
                msg = await self.r.read(max_msg_size)
                if not msg:
                    return 0

                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                ).derive(self.shared)

                aesgcm = AESGCM(derived_key)
                msg, nonce = msg[:-12], msg[-12:]
                decrypted = aesgcm.decrypt(nonce, msg, None)
                await self.processMsg(decrypted)
            except Warning as w:
                print(f"\033[93m[WARN] while processing server response: {w}\033[0m")
                return 1
            except Exception as e:
                print(f"\033[91m[ERROR] while processing server response: {e}\033[0m")
                return 0

        return status
            

        


async def tcp_echo_client():
    """Establishes a TCP connection to the server and handles client operations."""
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(reader, writer, addr)

    async def shutdown_connection():
        """Helper to close this client connection gracefully."""
        # try sending a newline terminator if we can
        try:
            writer.write(b'\n')
            await writer.drain()
        except Exception:
            pass

        # now close the transport
        writer.close()
        await writer.wait_closed()
        print('Socket closed!')

    try:
        # --- load keystore and certificates ---
        private_key, user_cert, _ = login_ui()
        if private_key is None or user_cert is None:
            print("\033[91m[ERROR] Missing private key or user certificate\033[0m")
            return
        
        # --- validate client certificate ---
        if not validate_cert(CA_cert, user_cert, None):
            print("\033[91m[ERROR] Client's certificate is invalid\033[0m")
            return

        # --- configure client worker ---
        client.set_RSA_priv_key(private_key)
        client.set_cli_cert(user_cert)
        client.load_public_key()
        client.set_cli_id()

        # --- generate & serialize our public key ---
        cli_pubkey = client.getPublic()
        cli_pubkey_bytes = pubkey_bytes(cli_pubkey)
        if cli_pubkey_bytes is None:
            print("\033[91m[ERROR] Unable to encode public key\033[0m")
            return

        # --- send our pubkey, receive server’s ---
        writer.write(cli_pubkey_bytes)
        await writer.drain()

        sv_pubkey_sig_cert = await reader.read(max_msg_size)
        sv_pubkey, sv_sig, sv_cert_bytes = decouple(sv_pubkey_sig_cert)
        sv_cert = bytes_to_cert(sv_cert_bytes)

        # --- validate server certificate ---
        if not validate_cert(CA_cert, sv_cert, "vault_sv"):
            print("\033[91m[ERROR] Server's certificate is invalid\033[0m")
            return

        # --- verify server signature ---
        RSA_sv_pubkey = sv_cert.public_key()
        if not isinstance(RSA_sv_pubkey, rsa.RSAPublicKey):
            print("\033[91m[ERROR] Invalid RSA public key\033[0m")
            return

        message = sv_pubkey + cli_pubkey_bytes
        if not validate_signature(RSA_sv_pubkey, sv_sig, message):
            print("\033[91m[ERROR] Signature validation failed\033[0m")
            return

        # --- send our signature + certificate ---
        cli_sig = client.sign(cli_pubkey_bytes + sv_pubkey)
        if cli_sig is None:
            print("\033[91m[ERROR] Unable to sign message\033[0m")
            return

        cli_cert_bytes = cert_to_bytes(client.cli_cert)
        writer.write(mkpair(cli_sig, cli_cert_bytes))
        await writer.drain()

        # --- derive shared key and enter processing loop ---
        client.generateShared(sv_pubkey)
        keep_going = True
        while keep_going:
            keep_going = await client.process()

    except (ConnectionResetError, asyncio.IncompleteReadError) as e:
        # expected connection-level errors
        print(f"\033[91m[ERROR] Connection lost: {e}\033[0m")

    except Exception as e:
        print(f"\033[91m[ERROR] Unexpected error: {e}\033[0m")

    finally:
        await shutdown_connection()


def run_client():
    """Runs the client by starting the asyncio event loop."""
    asyncio.run(tcp_echo_client())


if len(sys.argv) != 1:
    raise Exception("Usage: ./client.py")

run_client()
