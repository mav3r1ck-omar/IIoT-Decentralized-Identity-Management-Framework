import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import config


def save(path, data):
    with open(path, "wb") as f:
        f.write(data)


def generate():
    os.makedirs("certs", exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. our own Certificate Authority (the "zone CA") - devices will trust it
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IIoT Zone-A Root CA")])
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               # what this certificate may be used for: signing other certificates
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                            content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False,
                                            encipher_only=False, decipher_only=False), critical=True)
               # a fingerprint of the CA's own key
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
               .sign(ca_key, hashes.SHA256()))

    # 2. the fog's certificate, signed by the CA, valid for localhost / 127.0.0.1
    fog_key = ec.generate_private_key(ec.SECP256R1())
    fog_cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fog-A1")]))
                .issuer_name(ca_name)
                .public_key(fog_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=180))
                .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                # this is NOT a CA - it can't sign other certificates
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                             content_commitment=False, data_encipherment=False,
                                             key_agreement=True, key_cert_sign=False, crl_sign=False,
                                             encipher_only=False, decipher_only=False), critical=True)
                # it may only be used as a TLS server
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(fog_key.public_key()), critical=False)
                # "I was signed by THIS CA key" - the field your error said was missing
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                               critical=False)
                .sign(ca_key, hashes.SHA256()))

    save(config.CA_CERT, ca_cert.public_bytes(serialization.Encoding.PEM))
    save(config.FOG_CERT, fog_cert.public_bytes(serialization.Encoding.PEM))
    save(config.FOG_KEY, fog_key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    print("Certificates written to certs/ (ca.pem, fog.pem, fog-key.pem)")

if __name__ == "__main__":
    generate()