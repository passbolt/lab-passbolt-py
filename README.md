# py-passbolt

Python library for Passbolt API based on [httpx](https://www.python-httpx.org/) and [PGPy](https://pgpy.readthedocs.io/en/latest/)

## How to use

Create a config.json:

```
{
    "base_url": "https://passbolt.domain.tld",
    "private_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\r\n See below about how to convert your private key in one-line mode -----END PGP PRIVATE KEY BLOCK-----\r",
    "passphrase": "a-strong-passphrase"
} 
```

or use environment variables (PASSBOLT_BASEURL, PASSBOLT_PRIVATE_KEY, PASSBOLT_PASSPHRASE).

Then have a look at example.py python script
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