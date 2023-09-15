from __future__ import annotations

import os
import base64
from typing import Union, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_master_key() -> bytes:
    config_path = os.path.join("master.key")
    with open(config_path, "rb") as f:
        return f.read().strip()


def aes_generate_key(bit_length: int = 256) -> bytes:
    """
    Generates a base64 Key Compatible with AES-GCM/CHACHA20+POLY1305/FERNET
    """
    key = AESGCM.generate_key(bit_length=bit_length)
    return base64.urlsafe_b64encode(key)


def aes_gcm_encrypt(data: Union[bytes, str], associated_data: Optional[bytes] = None) -> bytes:
    """
    aes_gcm_encrypt encrypts data using AES GCM-256

    Params
    ------

        data: Union[str, bytes] | data that should be encrypted

        associated_data: Optional[bytes] | associated data that should be
        authenticated with key but not encrypted

    Returns
    -------
        base64 urlsafe encoded data that should be decrypted using
        flask_vault.lib.cryptography.aes.aes_gcm_decrypt: bytes
    """
    data = data if isinstance(data, bytes) else data.encode("utf-8")
    iv = os.urandom(12)
    return base64.urlsafe_b64encode(iv + AESGCM(memoryview(base64.urlsafe_b64decode(get_master_key()))).encrypt(iv, data, associated_data))  # type: ignore  # noqa


def aes_gcm_decrypt(data: Union[bytes, str], associated_data: Optional[bytes] = None) -> bytes:
    """
    aes_gcm_encrypt decrypts data encrypted with flask_vault.lib.cryptography.aes.aes_gcm_encrypt
    using AES GCM-256

    Params
    ------
        data: Union[str, bytes] | base64 urlsafe encoded data that should be decrypted

        associated_data: Optional[bytes] | associated data that should be authenticated with key but not encrypted

    Returns
    -------
        decrypted data: bytes
    """
    data = base64.urlsafe_b64decode(data if isinstance(data, bytes) else data.encode("utf-8"))
    return AESGCM(memoryview(base64.urlsafe_b64decode(get_master_key()))).decrypt(
        data[:12], data[12:], associated_data
    )  # noqa  # type: ignore
