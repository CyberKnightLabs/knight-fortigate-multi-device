"""Tests for the SSH part of the setup wizard (ssh_setup.py). No device, no real Keychain."""

from __future__ import annotations

import asyncssh
import keyring
import pytest

import ssh_setup


class FakeKey:
    def get_algorithm(self):
        return "ssh-ed25519"

    def get_fingerprint(self, _kind):
        return "SHA256:test"

    def export_public_key(self, _fmt):
        return b"ssh-ed25519 AAAATEST"


@pytest.fixture
def env(tmp_path, monkeypatch):
    store = {}
    monkeypatch.setattr(ssh_setup, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ssh_setup, "KNOWN_HOSTS", tmp_path / "known_hosts")
    monkeypatch.setattr(keyring, "set_password", lambda s, n, p: store.__setitem__((s, n), p))
    monkeypatch.setattr(keyring, "get_password", lambda s, n: store.get((s, n)))
    monkeypatch.setattr(keyring, "delete_password", lambda s, n: store.pop((s, n)))
    monkeypatch.setattr(asyncssh, "import_known_hosts", lambda text: text)

    async def fetch(host, port):
        return FakeKey()

    monkeypatch.setattr(ssh_setup, "_fetch_host_key", fetch)
    return store


def answers(monkeypatch, inputs, password="pw-123"):
    it = iter(inputs)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(it))
    monkeypatch.setattr(ssh_setup.getpass, "getpass", lambda _prompt="": password)


def test_configure_saves_only_after_successful_login(env, monkeypatch):
    async def login(*a):
        return "Version: FortiGate-40F v7.6.8"

    monkeypatch.setattr(ssh_setup, "_login", login)
    answers(monkeypatch, ["2222", "y", "diag-admin"])
    device = {"host": "10.0.0.1"}
    assert ssh_setup.configure_ssh("FGT", device) is True
    assert device == {"host": "10.0.0.1", "ssh_username": "diag-admin", "ssh_port": 2222}
    assert "pw-123" not in str(device)                       # password never in config
    assert env[(ssh_setup.SSH_SERVICE, "FGT")] == "pw-123"   # only in the credential store
    kh = ssh_setup.KNOWN_HOSTS
    assert kh.read_text().strip() == "[10.0.0.1]:2222 ssh-ed25519 AAAATEST"
    assert oct(kh.stat().st_mode & 0o777) == "0o600"
    assert ssh_setup.ssh_status("FGT", device) == "diag-admin@port 2222"


def test_failed_login_saves_nothing(env, monkeypatch):
    async def login(*a):
        raise asyncssh.PermissionDenied("denied")

    monkeypatch.setattr(ssh_setup, "_login", login)
    answers(monkeypatch, ["", "y", "admin"])
    device = {"host": "10.0.0.1"}
    assert ssh_setup.configure_ssh("FGT", device) is False
    assert device == {"host": "10.0.0.1"} and not env and not ssh_setup.KNOWN_HOSTS.exists()


def test_untrusted_host_key_stops(env, monkeypatch):
    answers(monkeypatch, ["", "n"])
    device = {"host": "10.0.0.1"}
    assert ssh_setup.configure_ssh("FGT", device) is False and not env


def test_remove_ssh_clears_everything(env, monkeypatch):
    ssh_setup.KNOWN_HOSTS.write_text("10.0.0.1 ssh-ed25519 A\n10.0.0.2 ssh-ed25519 B\n")
    env[(ssh_setup.SSH_SERVICE, "FGT")] = "pw"
    device = {"host": "10.0.0.1", "ssh_username": "admin", "ssh_port": 22}
    ssh_setup.remove_ssh("FGT", device)
    assert device == {"host": "10.0.0.1"} and not env
    assert ssh_setup.KNOWN_HOSTS.read_text() == "10.0.0.2 ssh-ed25519 B\n"   # other devices kept
    assert ssh_setup.ssh_status("FGT", device) == "not configured"


def test_change_password_tests_login_and_keeps_old_on_failure(env, monkeypatch):
    ssh_setup.KNOWN_HOSTS.write_text("10.0.0.1 ssh-ed25519 A\n")
    env[(ssh_setup.SSH_SERVICE, "FGT")] = "old-pw"
    device = {"host": "10.0.0.1", "ssh_username": "admin", "ssh_port": 22}

    async def bad_login(*a):
        raise asyncssh.PermissionDenied("denied")

    monkeypatch.setattr(ssh_setup, "_login", bad_login)
    monkeypatch.setattr(ssh_setup.getpass, "getpass", lambda _p="": "new-pw")
    assert ssh_setup.change_ssh_password("FGT", device) is False
    assert env[(ssh_setup.SSH_SERVICE, "FGT")] == "old-pw"          # old password kept

    async def good_login(*a):
        return "Version: FortiGate v7.6.8"

    monkeypatch.setattr(ssh_setup, "_login", good_login)
    assert ssh_setup.change_ssh_password("FGT", device) is True
    assert env[(ssh_setup.SSH_SERVICE, "FGT")] == "new-pw"
    assert device == {"host": "10.0.0.1", "ssh_username": "admin", "ssh_port": 22}   # nothing else changed


def test_change_password_needs_matching_repeat_and_configured_ssh(env, monkeypatch):
    assert ssh_setup.change_ssh_password("FGT", {"host": "10.0.0.1"}) is False
    ssh_setup.KNOWN_HOSTS.write_text("10.0.0.1 ssh-ed25519 A\n")
    seq = iter(["one", "two"])
    monkeypatch.setattr(ssh_setup.getpass, "getpass", lambda _p="": next(seq))
    assert ssh_setup.change_ssh_password("FGT", {"host": "10.0.0.1", "ssh_username": "a"}) is False
    assert not env
