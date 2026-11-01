"""Verifica a assinatura pelo bloco RSA recuperado, sem confiar no signer."""
import base64
import struct

import pytest

from openhdb import auth


@pytest.fixture(scope="module")
def key(tmp_path_factory):
    return auth.ensure_key(tmp_path_factory.mktemp("keys") / "test.pem")


def test_token_is_signed_prehashed(key):
    token = bytes(range(20))
    signature = auth.sign_token(key, token)
    n, e = auth.modulus_and_exponent(key)
    recovered = pow(int.from_bytes(signature, "big"), e, n).to_bytes(256, "big")
    digestinfo = auth._SHA1_DIGESTINFO + token
    expected = b"\0\x01" + b"\xff" * (256 - len(digestinfo) - 3) + b"\0" + digestinfo
    assert recovered == expected
    assert len(signature) == 256


@pytest.mark.parametrize("token", [b"", b"x" * 19, b"x" * 21])
def test_token_length(key, token):
    with pytest.raises(auth.AuthError):
        auth.sign_token(key, token)


def test_android_public_key_blob(key):
    blob = auth.android_public_key(key)
    n, e = auth.modulus_and_exponent(key)
    assert len(blob) == 524
    words, n0inv = struct.unpack_from("<II", blob)
    assert words == 64
    assert (n0inv * n) & 0xFFFFFFFF == 0xFFFFFFFF
    assert int.from_bytes(blob[8:264], "little") == n
    assert int.from_bytes(blob[264:520], "little") == pow(2, 4096, n)
    assert struct.unpack_from("<I", blob, 520)[0] == e
    encoded = auth.encoded_public_key(key, "test@host")
    assert base64.b64decode(encoded.split()[0], validate=True) == blob
    assert encoded.endswith(b" test@host")
    assert key.stat().st_mode & 0o777 == 0o600
