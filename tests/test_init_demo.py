import hashlib
import json
from pathlib import Path
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest


class InitDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scripts.init_demo import initialize

        cls.temporary = tempfile.TemporaryDirectory()
        cls.output = Path(cls.temporary.name) / "runtime"
        cls.paths = initialize(cls.output, host="demo.example", port=9555)
        cls.server = json.loads(Path(cls.paths["server_config"]).read_text())
        cls.alice = json.loads(Path(cls.paths["alice_config"]).read_text())
        cls.bob = json.loads(Path(cls.paths["bob_config"]).read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def config_path(self, config, name):
        path = Path(config[name])
        self.assertFalse(path.is_absolute())
        return self.output / path

    def test_configs_contain_real_certificate_identities_and_limits(self):
        self.assertEqual(self.server["host"], "127.0.0.1")
        self.assertEqual(self.server["port"], 9555)
        self.assertEqual(self.alice["host"], "demo.example")
        self.assertEqual(self.alice["port"], 9555)
        self.assertEqual(Path(self.paths["root"]), self.config_path(self.server, "root"))
        users = {user["name"]: user for user in self.server["users"]}
        for name, client, tier, rate, quota in (
            ("alice", self.alice, "Standard", 262144, 67108864),
            ("bob", self.bob, "VIP", 1048576, 134217728),
        ):
            pem = self.config_path(client, "certfile").read_text()
            fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
            self.assertEqual(users[name]["fingerprint"], fingerprint)
            self.assertEqual(users[name]["tier"], tier)
            self.assertEqual(users[name]["rate_bps"], rate)
            self.assertEqual(users[name]["quota_bytes"], quota)
            self.assertTrue(users[name]["can_upload"])
            self.assertTrue(users[name]["can_download"])
        self.assertNotEqual(users["alice"]["fingerprint"], users["bob"]["fingerprint"])
        self.assertNotIn("ca_key", self.server)

    def test_generated_certificates_have_restricted_purposes(self):
        openssl = shutil.which("openssl")
        cafile = str(self.config_path(self.server, "cafile"))
        for config, purpose, wrong_purpose in (
            (self.server, "sslserver", "sslclient"),
            (self.alice, "sslclient", "sslserver"),
            (self.bob, "sslclient", "sslserver"),
        ):
            certfile = str(self.config_path(config, "certfile"))
            valid = subprocess.run([openssl, "verify", "-CAfile", cafile,
                                    "-purpose", purpose, certfile], capture_output=True)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            invalid = subprocess.run([openssl, "verify", "-CAfile", cafile,
                                      "-purpose", wrong_purpose, certfile], capture_output=True)
            self.assertNotEqual(invalid.returncode, 0)

    def test_certificates_complete_real_mutually_authenticated_tls(self):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        server_context.load_cert_chain(self.config_path(self.server, "certfile"),
                                       self.config_path(self.server, "keyfile"))
        server_context.load_verify_locations(self.config_path(self.server, "cafile"))
        server_context.verify_mode = ssl.CERT_REQUIRED
        client_context = ssl.create_default_context(cafile=self.config_path(self.alice, "cafile"))
        client_context.load_cert_chain(self.config_path(self.alice, "certfile"),
                                       self.config_path(self.alice, "keyfile"))
        server_socket, client_socket = socket.socketpair()
        server_socket.settimeout(5)
        client_socket.settimeout(5)
        observed = []
        errors = []

        def serve():
            try:
                with server_context.wrap_socket(server_socket, server_side=True) as secure:
                    observed.append(secure.getpeercert()["subject"])
                    secure.sendall(secure.recv(5))
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            with client_context.wrap_socket(client_socket, server_hostname="demo.example") as secure:
                names = secure.getpeercert()["subjectAltName"]
                self.assertIn(("DNS", "localhost"), names)
                self.assertIn(("DNS", "demo.example"), names)
                self.assertIn(("IP Address", "127.0.0.1"), names)
                secure.sendall(b"hello")
                self.assertEqual(secure.recv(5), b"hello")
        finally:
            worker.join(timeout=6)
            server_socket.close()
            client_socket.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertIn((("commonName", "alice"),), observed[0])

    def test_private_permissions_and_demo_files(self):
        for path in [self.output] + list(self.output.rglob("*")):
            expected = 0o700 if path.is_dir() else 0o600
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, str(path))
        files = list((self.output / "demo-files").iterdir())
        self.assertTrue(any(any(ord(char) > 127 for char in path.name) for path in files))
        self.assertGreater(sum(path.stat().st_size for path in files), 1024 * 1024)

    def test_refuses_overwrite_and_invalid_input_before_creating_output(self):
        from scripts.init_demo import initialize

        key = self.config_path(self.alice, "keyfile")
        original = key.read_bytes()
        with self.assertRaises(FileExistsError):
            initialize(self.output)
        self.assertEqual(key.read_bytes(), original)
        for host, port in (("name\nDNS.4=bad", 9444), ("localhost", 0),
                           ("localhost", 65536), ("localhost", True)):
            fresh = Path(self.temporary.name) / "invalid"
            with self.assertRaises(ValueError):
                initialize(fresh, host=host, port=port)
            self.assertFalse(fresh.exists())

    def test_cli_generates_requested_configuration(self):
        destination = Path(self.temporary.name) / "cli-runtime"
        result = subprocess.run(
            [__import__("sys").executable, "-m", "scripts.init_demo", "--output",
             str(destination), "--host", "127.0.0.2", "--port", "9556"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        paths = json.loads(result.stdout)
        config = json.loads(Path(paths["alice_config"]).read_text())
        self.assertEqual((config["host"], config["port"]), ("127.0.0.2", 9556))


if __name__ == "__main__":
    unittest.main()
