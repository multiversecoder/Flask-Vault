from __future__ import annotations

import inspect
import traceback
import tomllib
import os
import sys
import shlex
import shutil
import stat
import subprocess
import tempfile
from typing import Dict, Any, Optional, cast
from flask_vault.lib.cryptography.aes import aes_gcm_decrypt, aes_gcm_encrypt

DEFAULT_TPL = """
# This file uses TOML to define secrets that are 
# encrypted using AES-GCM 128

# It uses the classic Key: Value syntax of TOML to add data.
# Example:
#    username =  "my_password"

# To call the key-value combinations in this file from external
# sources  use (get_secret("secret").get("name"))
# [smtp]
# port =  587  # For starttls
# server =  "smtp.gmail.com"
# username =  ""
# password =  ""
# sender =  "my@gmail.com"
# receiver =  "your@gmail.com"
#
"""

MSG_FAILED = "\n\tfailed! {msg}"
CREDENTIALS_ENC = "credentials.toml.enc"


def get_secret(secret: str) -> Optional[str]:
    if not os.path.exists(CREDENTIALS_ENC):
        return None
    with open(CREDENTIALS_ENC, "r") as f:
        ret = aes_gcm_decrypt(f.read())
    dump = tomllib.loads(ret.decode("utf-8"))
    try:
        ret = dump[secret].decode("utf-8") if isinstance(dump[secret], bytes) else dump[secret]
        del secret
        del dump
        return ret
    except (KeyError, TypeError) as e:
        return None
    return None



class Credentials:
    def _all_secrets(self) -> Optional[Dict[str, Any]]:
        try:
            with open(CREDENTIALS_ENC, "rb") as f:
                return dict(tomllib.loads(aes_gcm_decrypt(f.read()).decode("utf-8")))
        except FileNotFoundError:
            return None

    def _add(self, key: str, value: str, dc: bool = False) -> None:
        m: Dict[str, Any] = {}
        if os.path.exists(CREDENTIALS_ENC):
            m = self.all_secrets()  # type: ignore
            if not dc and key in m:
                raise FileExistsError(MSG_FAILED.format(msg=f"to create credentials with key: {key}"))  # noqa
        m[key] = value
        with open(CREDENTIALS_ENC, "wb+") as cenc:
            cenc.write(aes_gcm_encrypt(tomllib.dumps(m).encode("utf-8")))  # type: ignore
        del value, m

    def _edit(self, key: str, value: str) -> None:
        self._add(key, value, True)

    def _show(self, key: str) -> Optional[str]:
        m = self._all_secrets()
        if m is not None:
            try:
                return str(m[key])
            except KeyError:
                return None
        return None

    def edit(self) -> None:
        self.read_secret_in_editor(path=CREDENTIALS_ENC, edit=True)

    def show(self) -> None:
        self.read_secret_in_editor(path=CREDENTIALS_ENC, edit=False)

    @staticmethod
    def encrypt(f: str) -> None:
        with open(f, "rb") as uf:
            with open(f"{f}.enc", "wb+") as ef:
                ef.write(aes_gcm_encrypt(uf.read()))

    @staticmethod
    def _decrypt(f: str) -> Optional[bytes]:
        try:
            with open(f, "rb") as ef:
                return cast(bytes, aes_gcm_decrypt(ef.read()))
        except FileNotFoundError:
            return None

    def decrypt(self, f: str) -> None:
        self.read_secret_in_editor(path=f, edit=False)

    def read_secret_in_editor(self, path: str, edit: bool = False) -> None:
        ed = shutil.which(os.environ.get("EDITOR", "vi"))
        if not bool(ed):
            raise Exception(
                MSG_FAILED.format(
                    msg="EDITOR not found! Please set EDITOR=<your editor>")
            )
        with tempfile.NamedTemporaryFile("wb+", dir="tmp") as tmp:
            try:
                tmp.write(self._decrypt(path))  # type: ignore
            except ValueError:
                tmp.write(DEFAULT_TPL.encode("utf-8"))

            tmp.seek(0)
            if not edit:
                os.chmod(tmp.name, stat.S_IREAD)
            try:
                subprocess.Popen(shlex.split(f"{ed} {tmp.name}")).wait()
                if edit:
                    with open(tmp.name, "rb") as df:
                        with open(CREDENTIALS_ENC, "wb") as f:  # noqa
                            f.write(aes_gcm_encrypt(df.read()))
                    print(f"{CREDENTIALS_ENC} saved!")
            except BaseException as e:
                if edit:
                    print(MSG_FAILED.format(msg="Nothing saved!", end="\n"))
                    sys.exit(1)
                else:
                    print(MSG_FAILED.format(msg=traceback.format_exc(), end="\n"))
                    sys.exit(1)


_Credentials = Credentials()
