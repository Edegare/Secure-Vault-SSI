import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12


def cert_to_bytes(cert):
    cert_bytes = cert.public_bytes(
        encoding=serialization.Encoding.PEM)
    return cert_bytes


def bytes_to_cert(data):
    cert = x509.load_pem_x509_certificate(data)
    return cert


def cert_load(fname):
    """lê certificado de ficheiro"""
    with open(fname, "rb") as fcert:
        cert = bytes_to_cert(fcert.read())
    return cert


def cert_validtime(cert, now=None):
    """valida que 'now' se encontra no período
    de validade do certificado."""
    if now is None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise x509.verification.VerificationError(
            "Certificate is not valid at this time"
        )


def cert_validsubject(cert, attrs=[]):
    """verifica atributos do campo 'subject'. 'attrs'
    é uma lista de pares '(attr,value)' que condiciona
    os valores de 'attr' a 'value'."""
    for attr in attrs:
        if cert.subject.get_attributes_for_oid(attr[0])[0].value != attr[1]:
            raise x509.verification.VerificationError(
                "Certificate subject does not match expected value"
            )


def cert_validexts(cert, policy=[]):
    """valida extensões do certificado.
    'policy' é uma lista de pares '(ext,pred)' onde 'ext' é o OID de uma extensão e 'pred'
    o predicado responsável por verificar o conteúdo dessa extensão."""
    for check in policy:
        ext = cert.extensions.get_extension_for_oid(check[0]).value
        if not check[1](ext):
            raise x509.verification.VerificationError(
                "Certificate extensions does not match expected value"
            )


def validate_cert(ca_cert, subject_cert, subject_common_name) -> bool:
    try:
        # obs: pressupõe que a cadeia de certifica só contém 2 níveis
        subject_cert.verify_directly_issued_by(ca_cert)

        # verificar período de validade...
        cert_validtime(subject_cert)

        # verificar identidade... (e.g.)
        attr = [(x509.NameOID.COMMON_NAME, subject_common_name)]
        if subject_common_name is None:
            attr = []

        cert_validsubject(subject_cert, attr)

    except Exception as e:
        print("\033[91m[ERROR] Certificate validation failed:\033[0m")
        print(e)
        return False
    
    return True


def sign(RSA_privkey, message):
    if not isinstance(RSA_privkey, rsa.RSAPrivateKey):
        print("\033[91m[ERROR] Invalid private key type:\033[0m")
        print(type(RSA_privkey))
        return None

    return RSA_privkey.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def validate_signature(RSA_pubkey, sig, message) -> bool:
    try:
        RSA_pubkey.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        print("\033[91m[ERROR] Signature validation failed:\033[0m")
        print(e)
        return False
    
    return True


def get_userdata(p12_fname: str, password: str):
    with open(p12_fname, "rb") as f:
        p12 = f.read()

    private_key, user_cert, [ca_cert] = pkcs12.load_key_and_certificates(p12, password.encode())
    return (private_key, user_cert, ca_cert)