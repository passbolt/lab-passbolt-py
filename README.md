# Passbolt-Simple-Python-API
An easy to use and easy to understand, Windows compatible, Python script for using Passbolt API

Python Requirements: 
- httpx
- python-gnupg

Also you will need the GnuPG software, instructions and downloads can be found here:
https://gnupg.org/download/index.html
* for windows you need to download gpg4win, also found in the gnupg donwload page (scroll to the end). 

How to use:
- First you need to import your passbolt user Private Key to the gnupg, in Windows you do this through the Kleopatra software that comes in with gpg4win.
- Then you need to edit the base_url and gpgbinary variables in the __init__ function of the PassboltAPI, with your passbolt address (withou the last '/'), and the gpgbinary file location
- Last, you just instanciate the PassboltAPI passing your user fingerprint, it will then ask your passphrase, login, and get the CsrfToke setup for later use.

Then you can just use the already build functions to read/create/update your passbolt or create your own using mines as model. 

- example:
```python
def add_to_all_groups(user_email, is_admin=False):
    api = PassboltAPI('833DDC08501714B816AD6FFA2B56DC5702A012C0')
    user_id = api.get_user_by_email(user_email)['id']
    print(user_id)
    groups = api.get_groups()
    for group in groups:
        print(group['name'])
        print(api.put_user_on_group(group['id'], user_id, is_admin))
```

## How to import OpenPGP key in config.json file

### Linux:

```
sed -z 's/\n/\\n/g' zerocool.asc
```

### MacOS

Install `gnu-sed` with brew:

```
$ brew install gnu-sed
```

Use gsed instead of sed:

```
gsed -z 's/\n/\\n/g' zerocool.asc
```