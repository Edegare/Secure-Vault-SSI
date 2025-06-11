import os
import maskpass
import socket
import signal
import sys

from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12

P12_FILE = "ca/ca.p12"

def generate_ca(pwd: str):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Minho"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "G10 SSI CA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "G10 SSI CA VAULT SERVICE"),
        x509.NameAttribute(NameOID.PSEUDONYM, "SSI CA Root"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SSI CA Root"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(tz=timezone.utc))
        .not_valid_after(datetime.now(tz=timezone.utc) + timedelta(days=3650))
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    p12 = pkcs12.serialize_key_and_certificates(
        name=b"CA",
        key=ca_key,
        cert=ca_cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(pwd.encode())
    )

    with open(P12_FILE, "wb") as f:
        f.write(p12)

    print("[+] CA certificate generated.")

def handle_shutdown(signum, frame):
    print("\n[+] Shutting down CA server...")
    sys.exit(0)

def handle_csr_request(pwd: str):
    """
    Start a server to handle incoming CSR requests and return signed certificates.
    """
    signal.signal(signal.SIGINT, handle_shutdown)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 42069))  # Bind to the CA host and port
        sock.listen(5)
        print("[+] CA server is running and listening for CSR requests...")
        print("[+] Press Ctrl+C to shut down the server.")

        while True:
            client_socket, addr = sock.accept()
            with client_socket:
                print(f"[+] Connection established with {addr}")
                try:
                    # Receive the CSR
                    csr_data = client_socket.recv(4096)
                    csr = x509.load_pem_x509_csr(csr_data)

                    # Load CA key and cert
                    with open(P12_FILE, "rb") as f:
                        ca_key, ca_cert, _ = pkcs12.load_key_and_certificates(f.read(), pwd.encode())

                    # Verify the CSR signature to prove key‑possession
                    try:
                        csr.public_key().verify(
                            signature=csr.signature,
                            data=csr.tbs_certrequest_bytes,
                            padding=padding.PKCS1v15(),
                            algorithm=csr.signature_hash_algorithm
                        )
                    except Exception:
                        print("[-] CSR signature invalid — rejecting request")
                        client_socket.close()
                        continue

                    # Sign the CSR
                    cert = (
                        x509.CertificateBuilder()
                        .subject_name(csr.subject)
                        .issuer_name(ca_cert.subject)
                        .public_key(csr.public_key())
                        .serial_number(x509.random_serial_number())
                        .not_valid_before(datetime.now(tz=timezone.utc))
                        .not_valid_after(datetime.now(tz=timezone.utc) + timedelta(days=365))
                        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                        .sign(private_key=ca_key, algorithm=hashes.SHA256())
                    )

                    # Send the signed certificate back to the client
                    client_socket.sendall(cert.public_bytes(serialization.Encoding.PEM))
                    print("[+] Certificate signed and sent back to the client.")
                except Exception as e:
                    print(f"[ERROR] Failed to process CSR: {e}")
                    client_socket.close()
                    continue



if __name__ == "__main__":
    print("Please provide the CA's password")
    pwd = maskpass.askpass(mask="")  

    if not os.path.exists(P12_FILE):
        generate_ca(pwd)

    handle_csr_request(pwd)

