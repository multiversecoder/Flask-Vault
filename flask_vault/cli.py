import os
import inspect
import click
from typing import Optional
from flask_vault.lib.secrets import _Credentials, DEFAULT_TPL, get_secret, CREDENTIALS_ENC
from flask_vault.lib.cryptography.aes import aes_generate_key, aes_gcm_encrypt
from flask.cli import AppGroup

vault_cli = AppGroup("vault")


@vault_cli.command("init")
def secrets_init() -> None:
    """
    The flask vault init command will initialize the environment needed for Flask-Vault to operate.
    This command will create the credentials.yml.enc file, the master.key file and the tmp folder (which will be used internally by Flask-Vault).
    If you run this command a second time, no action will be taken since you will not be able to overwrite the created files.

    Command
    -------
        `flask vault init`

    Params
    ------
        None

    Returns
    -------
        None

    """
    if not os.path.exists("tmp"):
        click.secho("Creating the tmp directory...")
        os.mkdir("tmp")
    else:
        click.secho("`tmp` directory already exists!")
    if not os.path.exists("master.key"):
        with open("master.key", "wb+") as f:
            click.secho("Generating the `master.key` file to encrypt/decrypt stuff")
            f.write(aes_generate_key())
    else:
        click.secho("`master.key` file already exists!")
    if not os.path.exists(CREDENTIALS_ENC):
        with open(CREDENTIALS_ENC, "wb+") as f:
            click.secho(f"Creating `{CREDENTIALS_ENC}` file to store credentials")
            f.write(aes_gcm_encrypt(DEFAULT_TPL))
    else:
        click.secho("`credentials.yml.enc` file already exists!")


@vault_cli.command("show")
def secrets_show() -> None:
    """
    The flask vault show command will decrypt the contents of the credentials.yml.enc file using master.key and open it in read-only mode to show the saved credentials.

    Command
    -------
        `flask vault show`

    Params
    ------

    Returns
    -------
        None
    """

    _Credentials.show()


@vault_cli.command("get")
@click.argument("key")
def secrets_get(key: str) -> None:
    """
    The flask vault get command will decrypt credentials.yml.enc and display the selected secret in terminal.


    If the key does not exists "`No value for `key`" will be showed

    Command
    --------
        `flask vault get [key]`

    Params
    ------
        key: str The name of the key prensent inside `credentials.yml.enc`

    Returns
    -------
        None
    """
    secret = get_secret(key)
    if secret is None:
        click.secho(f"No value for {key}")
    else:
        click.secho(get_secret(key))


@vault_cli.command("edit")
def secrets_edit() -> None:
    """
    The flask vault show command will decrypt the contents of the credentials.yml.enc file using master.key and open it in edit mode.

    Command
    -------
        `flask vault edit`

    Params
    ------
        None

    Returns
    -------
        None
    """
    _Credentials.edit()


@vault_cli.command("encrypt")
@click.argument("file")
def secrets_encrypt(file: str) -> None:
    """
    The flask vault encrypt command will create an encrypted file.
    The generated file will be protected by AES-GCM encryption and will use a .enc extension to distinguish it from the plaintext file.

    Command
    -------
        flask vault encrypt [file]

    Params
    ------
        file: str


    Returns
    -------
        None

    """
    _Credentials.encrypt(file)


@vault_cli.command("decrypt")
@click.argument("file")
def secrets_decrypt(file: str) -> None:
    """
    The flask vault decrypt command will decrypt a file with the `.enc` extension and display its contents in the terminal.

    Command
    -------
        flask vault encrypt [file]

    Params
    ------
        file: str


    Returns
    -------
        None

    """
    _Credentials.decrypt(file)


@vault_cli.command("help")
@click.argument("command", required=False, default=None)
def secrets_help(command: Optional[str] = None) -> None:
    if command is None or command == "help":
        for cmd in ("init", "show", "get", "edit", "encrypt", "decrypt"):
            click.secho(f"[flask vault {cmd}]:\n")
            click.secho(inspect.cleandoc(globals()[f"secrets_{cmd}"].__doc__.split("Params\n")[0].strip()))
            click.secho("\n")
    else:
        try:
            click.secho(inspect.cleandoc(globals()[f"secrets_{command}"].__doc__.split("Params\n")[0].strip()))
        except KeyError:
            click.secho(f"Missing `flask vault` {command} command\n")
