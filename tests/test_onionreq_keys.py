"""
Onion request decryption with the X25519 conversion of the required [keys] quic (Ed25519) key, with
and without the [keys] onionreq (X25519) key.  Needs the spns_hivemind module on the path, e.g.:

    PYTHONPATH=.:buildz python3 -m pytest tests/test_onionreq_keys.py
"""

import hashlib
import hmac
import json
import struct

import nacl.hashlib
import nacl.utils
import pytest
from Cryptodome.Cipher import AES
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_scalarmult,
    crypto_sign_ed25519_pk_to_curve25519,
)
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from spns import conf, onion_decrypt

X_KEY = PrivateKey.generate()
ED_KEY = SigningKey.generate()
# What a client encrypts to, knowing only each key's pubkey.
X_PUB = X_KEY.public_key.encode()
ED_X_PUB = crypto_sign_ed25519_pk_to_curve25519(ED_KEY.verify_key.encode())

ENC_TYPES = ("xchacha20", "aes-gcm")


def shared_key(eph, server_pub, enc_type):
    aB = crypto_scalarmult(eph.encode(), server_pub)
    # The onion request protocol's AES-GCM key, unlike its XChaCha20 one.
    if enc_type == "aes-gcm":
        return hmac.new(b"LOKI", aB, hashlib.sha256).digest()
    return nacl.hashlib.blake2b(
        aB + eph.public_key.encode() + server_pub, digest_size=32
    ).digest()


def build_request(server_pub, payload, enc_type):
    """A v4 onion request for the last hop, as a client would build it; and the key its reply is
    encrypted with."""
    eph = PrivateKey.generate()
    key = shared_key(eph, server_pub, enc_type)
    if enc_type == "aes-gcm":
        iv = nacl.utils.random(12)
        enc, mac = AES.new(key, AES.MODE_GCM, iv).encrypt_and_digest(payload)
        blob = iv + enc + mac
    else:
        nonce = nacl.utils.random(24)
        blob = nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(payload, None, nonce, key)
    outer = {
        "host": "localhost",
        "port": 80,
        "protocol": "http",
        "target": "/oxen/v4/lsrpc",
        "ephemeral_key": eph.public_key.encode().hex(),
        "enc_type": enc_type,
    }
    return struct.pack("<i", len(blob)) + blob + json.dumps(outer).encode(), key


def decrypt_reply(data, key, enc_type):
    if enc_type == "aes-gcm":
        return AES.new(key, AES.MODE_GCM, data[:12]).decrypt_and_verify(data[12:-16], data[-16:])
    return crypto_aead_xchacha20poly1305_ietf_decrypt(data[24:], None, data[:24], key)


@pytest.fixture
def load(tmp_path):
    """Loads a config with the given onion request keys (any of "onionreq", "quic")."""
    (tmp_path / "hivemind").write_bytes(PrivateKey.generate().encode())
    (tmp_path / "onionreq").write_bytes(X_KEY.encode())
    # Hex, as session-router-config writes it.
    (tmp_path / "quic").write_text(
        ED_KEY.encode().hex() + ED_KEY.verify_key.encode().hex() + "\n"
    )

    def load(*keys):
        ini = tmp_path / "spns.ini"
        ini.write_text(
            "[keys]\n"
            + "".join(f"{k} = {tmp_path / k}\n" for k in ("hivemind",) + keys)
        )
        conf.load_config(str(ini))
        return conf.ONIONREQ_KEYS

    return load


@pytest.mark.parametrize(
    "configured",
    [("quic",), ("onionreq", "quic"), ("quic", "onionreq")],
)
@pytest.mark.parametrize("enc_type", ENC_TYPES)
def test_decrypts_with_configured_keys(load, configured, enc_type):
    keys = load(*configured)
    # Whichever order the ini lists them in, onionreq is tried first.
    assert [k[0] for k in keys] == [k for k in ("onionreq", "quic") if k in configured]

    for name, server_pub in (("onionreq", X_PUB), ("quic", ED_X_PUB)):
        payload = f"l{name} payload e".encode()
        data, key = build_request(server_pub, payload, enc_type)
        if name not in configured:
            with pytest.raises(ValueError):
                onion_decrypt.decrypt(data, keys)
            continue
        parser, used = onion_decrypt.decrypt(data, keys)
        assert used == name
        assert parser.payload == payload
        assert decrypt_reply(parser.encrypt_reply(b"reply"), key, enc_type) == b"reply"


def test_rejects_request_for_neither_key(load):
    keys = load("onionreq", "quic")
    data, _ = build_request(PrivateKey.generate().public_key.encode(), b"le", "xchacha20")
    with pytest.raises(ValueError, match="tried 2"):
        onion_decrypt.decrypt(data, keys)


@pytest.mark.parametrize("configured", [(), ("onionreq",)])
def test_requires_quic_key(load, configured):
    with pytest.raises(RuntimeError, match=r"\[keys\] quic is required"):
        load(*configured)


def test_rejects_inconsistent_quic_key(load, tmp_path):
    (tmp_path / "quic").write_bytes(
        ED_KEY.encode() + SigningKey.generate().verify_key.encode()
    )
    with pytest.raises(RuntimeError, match="does not yield pubkey"):
        load("quic")
