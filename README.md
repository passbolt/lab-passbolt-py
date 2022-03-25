# py-passbolt

Python library for Passbolt API based on [httpx](https://www.python-httpx.org/) and [PGPy](https://pgpy.readthedocs.io/en/latest/).

You can also use [python-gnupg](https://docs.red-dove.com/python-gnupg/) if needed but it is not the default.

## How to install

```
python -m pip install py-passbolt
```
## How to use

### config.json configuration file

Basically, create a `config.json` file containing needed configuration. You will find samples:

* For PGPy (default): [config.json.PGPy.sample](https://gitlab.com/AnatomicJC/py-passbolt/-/blob/main/config.json.PGPy.sample)
* For python-gnupg: [config.json.gnupg.sample](https://gitlab.com/AnatomicJC/py-passbolt/-/blob/main/config.json.gnupg.sample)

Then have a look at [https://gitlab.com/AnatomicJC/py-passbolt/-/blob/main/example.py](example.py) python script.

### Environment variables

Mandatory:

* PASSBOLT_BASE_URL: Your passbolt URL

For PGPy:

* PASSBOLT_PRIVATE_KEY: Your passbolt private key in one-line format (See below about how to format)
* PASSBOLT_PASSPHRASE: Your passbolt passphrase

For python-gnupg:

* PASSBOLT_GPG_BINARY (Optional): path to your gpg binary, default to "gpg"
* PASSBOLT_GPG_LIBRARY: Set this to gnupg, otherwise it will be the default "PGPy"
* PASSBOLT_FINGERPRINT: The OpenPGP key fingerprint to use
## How to set OpenPGP key in config.json or environment variables

### Linux:

```
sed -z 's/\n/\\n/g' private.asc
```

### MacOS

Install `gnu-sed` with brew:

```
$ brew install gnu-sed
```

Use gsed instead of sed:

```
gsed -z 's/\n/\\n/g' private.asc
```