import os
import getpass
import socket

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12

from utils.cert_utils import cert_load

ca_port = 42069
ca_host = "127.0.0.1"


def create_account(username, password):
    """
    Create a new account by generating a new PKCS12 file with a CSR request to the CA program.
    The username serves as the PKCS12 file name and CSR subject common name.
    """
    # Generate our key
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "G10 SSI USER"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "G10 SSI USER VAULT SERVICE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Minho"),
        x509.NameAttribute(NameOID.PSEUDONYM, username), # The username serves as the pseudonym
        x509.NameAttribute(NameOID.COMMON_NAME, username), # The username serves as the common name
    ])).sign(client_key, hashes.SHA256()) # Sign the CSR with our private key.

    csr_bytes = csr.public_bytes(encoding=serialization.Encoding.PEM)

    # Send the CSR to the CA program and get the user certificate
    with socket.create_connection((ca_host, ca_port)) as sock:
        sock.sendall(csr_bytes)
        sock.shutdown(socket.SHUT_WR)
        response = sock.recv(4096)
    
    try:
        certificate = x509.load_pem_x509_certificate(response)
    except Exception as e:
        raise Exception(f"Failed to load certificate from CA response: {e}")
    
    ca_cert = cert_load("crt/ca.crt")
    if not ca_cert:
        raise Exception("Failed to load CA certificate.")
    
    # Create a PKCS12 file with the private key and user certificate
    client_p12 = pkcs12.serialize_key_and_certificates(
        name=username.encode(),
        key=client_key,
        cert=certificate,
        cas=[ca_cert],  # include CA in chain
        encryption_algorithm=BestAvailableEncryption(password.encode())
    )

    # Write client .p12 file
    with open(f"p12/{username}.p12", "wb") as f:
        f.write(client_p12)

    return client_p12



def login_ui():
    """
    General purpose login UI.
    It will first ask if the user wants to create a new acount or load an existing one.
    Either way, it will ask for the username, serving as the PKCS12 file name and CSR subject common name.
    If the user chooses to create a new account, it will ask for a password and then create a new PKCS12 file by
    sending a CSR request to the CA program.
    If the user chooses to load an existing account, it will ask for the password.
    If the password is correct, it will return the private key, user certificate and CA certificate.
    """

    while True:
        choice = input("Do you want to create a new account (C) or load an existing one (L)? ").strip().upper()
        if choice in ['C', 'L']:
            break
        print("Invalid choice. Please enter 'C' or 'L'.")

    # the username servers as the PKCS12 file name and CSR subject common name
    username = input("Enter your username: ").strip()
    p12_fname = f"p12/{username}.p12"

    # user chose to create a new account — ask for a password and create a new PKCS12 file
    if choice == 'C':
        if os.path.exists(p12_fname):
            print(f"Account '{username}' already exists.")
            print("Are you sure you want to overwrite it? (y/n)")
            overwrite = input().strip().lower()
            if overwrite != 'y':
                print("Account creation cancelled.")
                return None, None, None
            
        print("Creating a new account...")
        
        password = getpass.getpass("Enter your password: ").strip()
        
        p12 = create_account(username, password)
        private_key, user_cert, [ca_cert] = pkcs12.load_key_and_certificates(p12, password.encode())

    # user chose to load an existing account — ask for the password and load the PKCS12 file
    else:
        if not os.path.exists(p12_fname):
            print(f"Account '{username}' does not exist.")
            return None, None, None
        
        password = getpass.getpass("Enter your password: ").strip()
        
        try:
            with open(p12_fname, "rb") as f:
                p12 = f.read()
        except Exception as e:
            print(f"Error loading PKCS12 file: {e}")
            return None, None, None

        private_key, user_cert, [ca_cert] = pkcs12.load_key_and_certificates(p12, password.encode())

    return private_key, user_cert, ca_cert