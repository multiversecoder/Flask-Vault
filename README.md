# About Flask Vault

[**Flask-Vault**](https://github.com/multiversecoder/Flask-Vault) provides several cli commands to store secrets that you do not want to keep in the clear, using symmetric encryption with **AES-GCM**. These commands allow you to save very important credentials such as API keys, database credentials, etc.

In addition, **Flask-Vault** contains several helpers to simplify the encryption and decryption of data.

# Why Flask-Vault instead of Dotenv?

In the world of web development, safeguarding sensitive information is a paramount concern. When it comes to managing credentials when using [Flask](https://flask.palletsprojects.com/), two prominent options emerge: **Flask-Vault** and [Dotenv](https://github.com/theskumar/python-dotenv). While both have their merits, **Flask-Vault** stands out as the superior choice for securing critical data.

**Flask-Vault** offers a robust solution for protecting sensitive information. Stored in an encrypted credentials.yml.enc file, this data is shielded by an added layer of security. It can only be decrypted with the master key, ensuring that even if the file falls into the wrong hands, the information remains inaccessible.

Additionally, the encrypted editor, accessed through `flask vault edit`, allows for secure direct editing of the credentials file. This feature is invaluable for making swift adjustments to sensitive information without compromising security.

While both **Flask-Vault** and **Dotenv** serve important functions, **Flask-Vault** stands as the superior choice for securing sensitive data. Its robust encryption and seamless integration within **Flask** make it the ideal solution for managing critical information. By prioritizing security without sacrificing accessibility, **Flask-Vault** empowers developers to build and maintain applications with the utmost confidence in their data protection measures.

# About Flask-Vault Cryptography

The encryption used by `flask_vault` is **AES-GCM** with a *128-bit key*.

### Why AES-GCM 128?

Here are some benefits of using AES-GCM with a 128-bit key:
- Security: AES-GCM is considered secure and is widely used in various applications including TLS (Transport Layer Security) for securing internet communication.

- Efficiency: AES-GCM is known for being relatively efficient in terms of computational resources. This is especially important in scenarios where computational power may be limited, such as on IoT (Internet of Things) devices.

- Fast Encryption and Decryption: AES-GCM is optimized for modern processors, which means that it can encrypt and decrypt data relatively quickly. This is important for performance-sensitive applications.

- Parallelization: AES-GCM encryption and decryption can be parallelized, which means that it can take advantage of multiple processing cores in modern CPUs.

-  Authenticated Encryption with Associated Data (AEAD): AES-GCM provides both confidentiality and integrity, which means that not only is the data encrypted, but it also includes a message authentication code (MAC) to verify that the data has not been tampered with.

- Nonce-Based: AES-GCM requires a unique initialization vector (IV), called a nonce, for each encryption operation. This means that even if you encrypt the same data with the same key multiple times, the ciphertext will be different, adding an extra layer of security.

- Widely Supported: AES-GCM is supported by many cryptographic libraries and frameworks, making it a practical choice for a wide range of applications.

- Compliance: AES-GCM is often recommended or required by various security standards and compliance frameworks.

# Flask-Vault Dependencies

Flask-Vault uses few dependencies to secure data and files, here are the 2 main dependencies of this library:
- [Cryptography](https://cryptography.io/)
- [PyYAML](https://pyyaml.org/)

```toml
python = ">=3.7"
cryptography = "^41.0.3"
pyyaml = "^6.0.1"
```

# Getting Started with Flask-Vault

### Installing

Install and update using [pip](https://pip.pypa.io/en/stable/getting-started/)

```sh
$> pip install Flask-Vault
```

Install and update using [poetry](https://python-poetry.org/)

```sh
$> poetry add Flask-Vault
```

# Documentation

## How to integrate Flask-Vault with your Flask application.

## Use `flask_vault.cli.vault_cli` to enable `Flask-Vault`.

```python 
from flask import Flask
from flask_vault.cli import vault_cli

app = Flask(__name__)

...
# Register Command using the 
app.cli.add_command(vault_cli)
...

```


## Using a different editor to show/edit credentials

The default editor used by `Flask-Vault` is **vi**.

The example below shows how to use an editor other than **vi** to show or edit credentials saved in `credentials.yml.enc`. As shown, the example will use `nano` editor to use the `flask vault show` command. 

```sh
$> EDITOR=nano flask vault show
```

## Cli Commands

- > **flask vault init**: The `flask vault init` command will initialize the environment needed for Flask-Vault to operate. This command will create the `credentials.yml.enc` file, the `master.key` file and the `tmp` folder (which will be used internally by Flask-Vault). If you run this command a second time, no action will be taken since you will not be able to overwrite the created files.
- > **flask vault get [secret_name]**: The `flask vault get` command will decrypt `credentials.yml.enc` and display the selected secret in terminal.
- > **flask vault show**: The `flask vault show` command will decrypt the contents of the `credentials.yml.enc` file using `master.key` and open it in read-only mode to show the saved credentials.
- > **flask vault edit**: The `flask vault show` command will decrypt the contents of the `credentials.yml.enc` file using `master.key` and open it in edit mode.
- > **flask vault encrypt [filename]**: The `flask vault encrypt` command will create an encrypted file. The generated file will be protected by AES-GCM encryption and will use a `.enc` extension to distinguish it from the plaintext file.
- > **flask vault decrypt [filename]**: The `flask vault decrypt` command will decrypt a file with the extension `.enc` and display its contents in the terminal.


## Encrypting data using `flask_vault.utils.aes_gcm_encrypt`

Encrypting data without exposing the encryption key within the application using `flask_vault.utils.aes_gcm_encrypt`

```python
from flask import Flask
from flask_vault.utils import aes_gcm_encrypt

app = Flask(__name__)


@app.route("/encrypted", methods=["GET"])
def encrypted():
    ctx = {
        "encrypted": aes_gcm_encrypt("my.app.secret")
    }
    return render_template("encrypted.html", **ctx)
```

## Decrypting data using `flask_vault.utils.aes_gcm_decrypt`

Decrypting data without exposing the encryption key within the application using `flask_vault.utils.aes_gcm_decrypt`

```python 
from flask import Flask
from flask_vault.utils import aes_gcm_decrypt


app = Flask(__name__)

@æpp.route("/decrypt", methods=["GET"])
def decrypt():
    encrypted_data = request.args.get("encrypted", None)
    ctx = {
        "plaintext": aes_gcm_decrypt(encrypted_data) if encrypted_data is not None else "Missing encrypted data!"
    }
    return render_template("decrypt.html", **ctx)
```

## Obtaining credentials stored inside the `credentials.yml.enc` file

The example below shows how to get secrets from the `credentials.yml.enc` file using Flask-Vault's `get_secrets` function. In this example `get_secret` will be used to configure the database, preventing anyone who does not have access to the `master.key` from reading the username, password, and database name in clear text


#### credentials.yml.enc (after editing)

```yaml
---
# ... other stuff
db.name: my-db-name
db.username: root
db.password: my-db-password
```

### How to get secrets from `credentials.yml.enc`

Use the `flask_vault.utils.get_secret` function to obtain secrets and credentials stored inside the `credentials.yml.enc` file.

#### app.py using `flask_vault.utils.get_secret`
```python
import sys
import mariadb
from flask import Flask, request, g
from flask_vault.utils import get_secret

app = Flask(__name__)

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        try:
            conn = mariadb.connect(
                user=get_secret("db.username"),
                password=get_secret("db.password")
                host="127.0.0.1",
                port=3306,
                database=get_secret("db.name"),
            )
            db = g._database = conn 
        except mariadb.Error as e:
            print(f"Error connecting to MariaDB Platform: {e}")
            sys.exit(1)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()
```

# Contributing

Questions, comments or improvements, please create an issue on [Github](https://github.com/multiversecoder/Flask-Vault/issues).

To suggest a change to the code or documentation, please create a new pull request on GitHub. Also, please squash multiple commits into a single commit in your pull request by rebasing onto the master branch.


# Donation

If you feel that my work has been useful and you are interested in supporting this project and any future projects, please leave me a donation using one of the following cryptocurrencies.


- **Bitcoin (Segwit)**: `bc1q8vnltjge25dks05tv49eknvrar6pzu7837mnvt`

# License

MIT License

Copyright (c) 2023-present Adriano Romanazzo <github.com/multiversecoder>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
