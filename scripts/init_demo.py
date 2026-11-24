"""Create fresh local development identities, configuration and demo files.

The CA is private to this demo. Its key stays in the generated directory and is
never referenced by the server configuration. No system trust store is changed.
"""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile


def _write_private(path, content):
    if isinstance(content, str):
        content = content.encode("utf-8")
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def _host_san(host):
    if not isinstance(host, str) or not host or len(host) > 253:
        raise ValueError("host must be a valid DNS name or IP address")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
               for label in labels):
            raise ValueError("host must be a valid DNS name or IP address")
        return "DNS:" + host
    return "IP:" + str(address)


def initialize(output: Path, host="localhost", port=9444) -> dict:
    """Generate a new demo directory; refuse any existing output path.

    Returned paths are absolute. Paths inside JSON configurations are relative
    to those configuration files, so the directory can be moved as a unit.
    On a generation error, leave the private partial directory for inspection;
    a subsequent attempt must use a fresh directory instead of replacing keys.
    """
    configured_san = _host_san(host)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    output = Path(output).expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("Refusing to overwrite an existing demo directory: " + str(output))
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("OpenSSL CLI is required to initialize the local demo")
    output.mkdir(mode=0o700, parents=True)
    output.chmod(0o700)
    certs = output / "certs"
    root = output / "state"
    demo_files = output / "demo-files"
    for directory in (certs, root, demo_files):
        directory.mkdir(mode=0o700)

    def run(*arguments):
        try:
            subprocess.run([openssl] + [str(argument) for argument in arguments],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, umask=0o077)
        except subprocess.CalledProcessError as error:
            raise RuntimeError("OpenSSL certificate generation failed: " + error.stderr.strip()) from error

    def key(path):
        run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path)
        path.chmod(0o600)

    ca_key = certs / "ca.key"
    ca_cert = certs / "ca.pem"
    with tempfile.TemporaryDirectory(prefix=".certificate-setup-", dir=str(output)) as temporary:
        temporary = Path(temporary)
        temporary.chmod(0o700)
        ca_config = temporary / "ca.cnf"
        _write_private(ca_config, """[req]
distinguished_name = dn
prompt = no
x509_extensions = ca_ext
[dn]
CN = Harbor Local Demo CA
[ca_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
""")
        key(ca_key)
        run("req", "-new", "-x509", "-sha256", "-days", "3650", "-key", ca_key,
            "-config", ca_config, "-out", ca_cert)
        ca_cert.chmod(0o600)
        sans = list(dict.fromkeys(["DNS:localhost", "IP:127.0.0.1", configured_san]))
        for name, common_name, purpose in (("server", "localhost", "serverAuth"),
                                            ("alice", "alice", "clientAuth"),
                                            ("bob", "bob", "clientAuth")):
            private_key = certs / (name + ".key")
            certificate = certs / (name + ".pem")
            request = temporary / (name + ".csr")
            profile = temporary / (name + ".cnf")
            san_extension = "subjectAltName = " + ",".join(sans) + "\n" if name == "server" else ""
            _write_private(profile, """[req]
distinguished_name = dn
prompt = no
[dn]
CN = """ + common_name + """
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = """ + purpose + "\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n" + san_extension)
            key(private_key)
            run("req", "-new", "-sha256", "-key", private_key, "-config", profile, "-out", request)
            run("x509", "-req", "-sha256", "-days", "365", "-in", request,
                "-CA", ca_cert, "-CAkey", ca_key, "-set_serial", str(secrets.randbits(159) or 1),
                "-extfile", profile, "-extensions", "leaf", "-out", certificate)
            certificate.chmod(0o600)

    users = []
    for name, tier, rate, quota in (("alice", "Standard", 262144, 67108864),
                                    ("bob", "VIP", 1048576, 134217728)):
        der = ssl.PEM_cert_to_DER_cert((certs / (name + ".pem")).read_text(encoding="ascii"))
        users.append({"name": name, "fingerprint": hashlib.sha256(der).hexdigest(),
                      "tier": tier, "rate_bps": rate, "quota_bytes": quota,
                      "can_upload": True, "can_download": True})
        client = {"host": host, "port": port, "cafile": "certs/ca.pem",
                  "certfile": "certs/" + name + ".pem", "keyfile": "certs/" + name + ".key",
                  "label": name + " · " + tier}
        _write_private(output / (name + ".json"), json.dumps(client, ensure_ascii=False, indent=2) + "\n")
    server = {"host": "127.0.0.1", "port": port, "certfile": "certs/server.pem",
              "keyfile": "certs/server.key", "cafile": "certs/ca.pem", "root": "state", "users": users}
    _write_private(output / "server.json", json.dumps(server, ensure_ascii=False, indent=2) + "\n")
    marker = secrets.token_hex(4)
    _write_private(demo_files / ("中文演示说明-" + marker + ".txt"),
                   "Harbor 安全文件传输演示\n此文件由初始化脚本生成，可用于校验中文文件名和 UTF-8 文本传输。\n演示编号：" + marker + "\n")
    for kibibytes in (512, 2048):
        _write_private(demo_files / ("sample-" + str(kibibytes) + "KiB-" + marker + ".bin"),
                       secrets.token_bytes(kibibytes * 1024))
    return {"server_config": str(output / "server.json"),
            "alice_config": str(output / "alice.json"),
            "bob_config": str(output / "bob.json"), "root": str(root)}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Create fresh Harbor local mTLS identities and demo configuration")
    parser.add_argument("--output", type=Path, default=Path("runtime"))
    parser.add_argument("--host", default="localhost", help="Hostname clients verify against the server certificate")
    parser.add_argument("--port", type=int, default=9444)
    arguments = parser.parse_args(argv)
    try:
        paths = initialize(arguments.output, arguments.host, arguments.port)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, "Initialization failed: " + str(error) + "\n")
    print(json.dumps(paths, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
