#!/usr/bin/env python3
"""Generate a local test CA and server certificate for cgss-relive integration.

All private material is written under ``work/`` by default and is ignored by
Git. This is for a dedicated rooted test device only; it is not a production PKI
helper. One leaf may contain multiple DNS/IP SANs so a single TLS mux can serve
the original API and resource hostnames on device port 443.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
from collections.abc import Iterable
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_HOSTNAME = "apis.game.starlight-stage.jp"


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _unique_hostnames(primary: str, additional: Iterable[str] | None) -> list[str]:
    names: list[str] = []
    for value in [primary, *(additional or ())]:
        value = str(value).strip()
        if not value:
            raise ValueError("certificate hostname must not be empty")
        if value not in names:
            names.append(value)
    return names


def generate(
    output: Path,
    hostname: str = DEFAULT_HOSTNAME,
    *,
    additional_hostnames: Iterable[str] | None = None,
    days: int = 30,
) -> dict[str, Path]:
    output.mkdir(parents=True, exist_ok=True)
    hostnames = _unique_hostnames(hostname, additional_hostnames)
    now = dt.datetime.now(dt.timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cgss-relive local test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=max(days, 1) + 7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    san_entries: list[x509.GeneralName] = []
    for value in hostnames:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            san_entries.append(x509.DNSName(value))

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=max(days, 1)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    paths = {
        "ca_key": output / "ca.key.pem",
        "ca_cert": output / "ca.cert.pem",
        "server_key": output / "server.key.pem",
        "server_cert": output / "server.cert.pem",
        "server_chain": output / "server.chain.pem",
    }
    _write_private_key(paths["ca_key"], ca_key)
    paths["ca_cert"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_private_key(paths["server_key"], leaf_key)
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    paths["server_cert"].write_bytes(leaf_pem)
    paths["server_chain"].write_bytes(leaf_pem + ca_cert.public_bytes(serialization.Encoding.PEM))
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate cgss-relive rooted-device TLS test material")
    parser.add_argument(
        "--hostname",
        action="append",
        dest="hostnames",
        help=(
            "DNS/IP SAN; repeat for a multi-SAN certificate. "
            f"Default: {DEFAULT_HOSTNAME}"
        ),
    )
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("-o", "--output", type=Path, default=Path("work/tls"))
    args = parser.parse_args()

    hostnames = args.hostnames or [DEFAULT_HOSTNAME]
    paths = generate(
        args.output,
        hostnames[0],
        additional_hostnames=hostnames[1:],
        days=args.days,
    )
    print("generated local test CA + server certificate for:")
    for hostname in hostnames:
        print(f"  SAN: {hostname}")
    for name, path in paths.items():
        print(f"{name}: {path}")
    print("keep ca.key.pem and server.key.pem local; work/ and *.pem are gitignored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())