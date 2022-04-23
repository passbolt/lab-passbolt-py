import httpx
from pprint import pprint
import json
from urllib.parse import unquote
from pathlib import Path
import os
from pgpy import PGPKey, PGPMessage
import gnupg

# https://pgpy.readthedocs.io/en/latest/examples.html


class PassboltAPI:
    def __init__(
        self,
        dict_config=dict(),
    ):

        self.load_config(
            dict_config=dict_config,
        )

        # Load key
        if self.config.get("gpg_library", "PGPy") == "gnupg":
            self.gpg = gnupg.GPG(gpgbinary=self.config.get("gpgbinary", "gpg"))
            self.fingerprint = self.config.get("fingerprint", "")
        else:
            self.key, _ = PGPKey.from_blob(self.config.get("private_key"))
            self.fingerprint = self.key.fingerprint.replace(" ", "")

        self.base_url = self.config.get("base_url")
        self.login_url = f"{self.base_url}/auth/login.json"
        self.users_url = f"{self.base_url}/users.json"
        self.me_url = f"{self.base_url}/users/me.json"
        self.groups_url = f"{self.base_url}/groups.json"

        # vars definition
        self.authenticated = False
        self.token = None
        self.user_id = None
        self.pgp_message = None
        self.nonce = None

        self.session = httpx.Client()
        self.cookies = httpx.Cookies()

        self.login()

        # resource types
        self.resource_types = self.get_resource_type_ids()

    def load_config(
        self,
        dict_config=dict(),
    ):

        if dict_config:
            self.config = dict_config
        else:
            self.config = {
                "gpg_binary": os.environ.get("PASSBOLT_GPG_BINARY", "gpg"),
                "gpg_library": os.environ.get("PASSBOLT_GPG_LIBRARY", "PGPy"),
                "base_url": os.environ.get("PASSBOLT_BASE_URL", "https://undefined"),
                "private_key": os.environ.get("PASSBOLT_PRIVATE_KEY", "undefined"),
                "passphrase": os.environ.get("PASSBOLT_PASSPHRASE", "undefined"),
                "fingerprint": os.environ.get("PASSBOLT_FINGERPRINT", "undefined"),
            }

    def stage1(self):
        post = {"data": {"gpg_auth": {"keyid": self.fingerprint}}}

        response = self.session.post(self.login_url, json=post)
        decoded_response = json.loads(response.text)

        if decoded_response["header"]["code"] == 200:
            pgp_message = unquote(
                response.headers.get("x-gpgauth-user-auth-token")
            ).replace("\\+", " ")
            return pgp_message

        else:
            pprint(decoded_response)

    def decrypt(self, message):
        if self.config.get("gpg_library", "PGPy") == "gnupg":
            decrypt = self.gpg.decrypt(message)
            return decrypt
        else:
            # can return str ou bytearray
            pgp_message = PGPMessage.from_blob(message)
            with self.key.unlock(self.config.get("passphrase")):
                return self.key.decrypt(pgp_message).message

    def encrypt(self, message, public_key):
        """
        Encrypt a message for a given public key

        :param message: message to encrypt
        :type message: str
        :public_key: passbolt gpgkey object
        :type public_key: dict
        :returns: Encrypted message
        :rtype: str
        """
        if type(message) is dict:
            message = json.dumps(message)
        if self.config.get("gpg_library", "PGPy") == "gnupg":
            self.gpg.import_keys(public_key["armored_key"])
            encrypt = self.gpg.encrypt(
                message,
                public_key["fingerprint"],
                always_trust=True,
                sign=self.fingerprint,
            )
            return str(encrypt)
        else:
            pubkey, _ = PGPKey.from_blob(public_key["armored_key"])
            pgp_message = PGPMessage.new(message)
            with self.key.unlock(self.config.get("passphrase")):
                pgp_message |= self.key.sign(pgp_message)
            return str(pubkey.encrypt(pgp_message))

    def stage2(self, nonce):
        post = {
            "data": {
                "gpg_auth": {"keyid": self.fingerprint, "user_token_result": nonce}
            }
        }

        response = self.session.post(self.login_url, json=post)
        decoded_response = json.loads(response.text)

        if decoded_response["header"]["code"] == 200:
            return True
        else:
            return False

    def get_cookie(self):
        response = self.session.get(self.me_url)
        token = response.headers.get("set-cookie")
        user_id = json.loads(response.text)
        self.user_id = user_id["body"]["id"]
        self.token = token[10:-8]
        self.session.headers = {"X-CSRF-Token": self.token}

    def check_login(self):
        response = self.session.get(self.base_url + "/")
        if response.status_code != 200:
            print("Falha no login")
            print(response)

    def login(self):
        self.pgp_message = self.stage1()
        if self.config.get("gpg_library", "PGPy") == "gnupg":
            self.nonce = self.decrypt(self.pgp_message)
        else:
            self.nonce = self.decrypt(self.pgp_message).decode()
        self.authenticated = self.stage2(str(self.nonce))
        self.get_cookie()
        self.check_login()

    def get_users(self):
        response = self.session.get(self.users_url)
        decoded_response = json.loads(response.text)
        return decoded_response["body"]

    def get_groups(self):
        response = self.session.get(self.groups_url)
        decoded_response = json.loads(response.text)
        return decoded_response["body"]

    def get_user_by_email(self, email):
        users = self.get_users()
        for user in users:
            if user["username"] == email:
                return user

    def get_user_by_id(self, id):
        users = self.get_users()
        for user in users:
            if user["id"] == id:
                return user

    def get_group_by_name(self, group_name):
        groups = self.get_groups()
        for group in groups:
            if group["name"] == group_name:
                return group

    def create_group(self, group_name):
        post = {
            "name": group_name,
            "groups_users": [{"user_id": self.user_id, "is_admin": True}],
        }

        response = self.session.post(self.groups_url, json=post)

        return response

    def put_user_on_group(self, group_id, user_id, admin=False):
        post = {
            "id": group_id,
            "groups_users": [{"user_id": user_id, "is_admin": admin}],
        }
        url = f"{self.base_url}/groups/{group_id}/dry-run.json"
        response = self.session.put(url, json=post)
        if response.status_code == 200:
            user_key = self.get_user_public_key(user_id)
            secrets = json.loads(response.text)["body"]["dry-run"]["Secrets"]

            secrets_list = []
            for secret in secrets:
                decrypted = self.decrypt(secret["Secret"][0]["data"])
                reencrypted = self.encrypt(str(decrypted), user_key)

                secrets_list.append(
                    {
                        "resource_id": secret["Secret"][0]["resource_id"],
                        "user_id": user_id,
                        "data": str(reencrypted),
                    }
                )

            post = {
                "id": group_id,
                "groups_users": [{"user_id": user_id, "is_admin": admin}],
                "secrets": secrets_list,
            }

            url = f"{self.base_url}/groups/{group_id}.json"
            response = self.session.put(url, json=post)
        else:
            print(response.headers)
            print()
            print(response.text)
            print()

        return response

    def get_group_by_id(self, group_id):
        groups = self.get_groups()
        for group in groups:
            if group["id"] == group_id:
                return group

    def get_group_user_id(self, group_id, user_id):
        user = self.get_user_by_id(user_id)
        for group in user["groups_users"]:
            if group["group_id"] == group_id:
                return group["id"]

    def update_user_to_group_admin(self, group_id, user_id):
        group_user_id = self.get_group_user_id(group_id, user_id)

        post = {
            "id": group_id,
            "groups_users": [{"id": group_user_id, "is_admin": True}],
        }
        url = f"{self.base_url}/groups/{group_id}/dry-run.json"
        response = self.session.put(url, json=post)
        if response.status_code == 200:
            url = f"{self.base_url}/groups/{group_id}.json"
            response = self.session.put(url, json=post)
        else:
            print(response.headers)
            print()
            print(response.text)
            print()

        return response

    def get_user_public_key(self, user_id):
        """
        Return a gpgkey dictionary based on passbolt user_id parameter

        {'armored_key': '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n'
                        'Version: OpenPGP.js v4.10.9\r\n'
                        'Comment: https:\\/\\/openpgpjs.org\r\n'
                        '\r\n'
                        '-----END PGP PUBLIC KEY BLOCK-----\r\n',
         'bits': 2048,
         'created': '2022-01-14T10:19:30+00:00',
         'deleted': False,
         'expires': None,
         'fingerprint': '1321159AE7BEE9EF9C4BBC7ECBAD2FB0C22FE70C',
         'id': '9a339ea9-ce31-40cc-8b66-f592e3d5acfa',
         'key_created': '2022-01-14T10:19:24+00:00',
         'key_id': 'C22FE70C',
         'modified': '2022-01-14T10:19:30+00:00',
         'type': 'RSA',
         'uid': 'John Doe <johndoe@domain.tld>',
         'user_id': 'd9143b6d-82bb-4093-9272-6471e222e990'}

        :param user_id: The passbolt user_id we want to retrieve
        :type user_id: str
        :returns: gpgkey dictionary
        :rtype: dict
        """
        url = f"{self.base_url}/users/{user_id}.json"
        response = self.session.get(url)

        user = json.loads(response.text)["body"]
        return user["gpgkey"]

    def get_resource_secret(self, resourceId):
        url = f"{self.base_url}/secrets/resource/{resourceId}.json"
        response = self.session.get(url)

        secrete_data = json.loads(response.text)["body"]["data"]
        return secrete_data

    def get_resources(self):
        url = f"{self.base_url}/resources.json"
        response = self.session.get(url)

        secrete_data = json.loads(response.text)["body"]
        return secrete_data

    def get_resource_per_uuid(self, uuid):
        url = f"{self.base_url}/resources/{uuid}.json"
        response = self.session.get(url)

        secrete_data = json.loads(response.text)["body"]
        return secrete_data

    def create_resource(self, resource):
        return self.session.post(f"{self.base_url}/resources.json", json=resource)

    def get_resource_types(self):
        """
        Returns all available resource types. Currently 2 resources types available:
        * password-string
        * password-and-description

        :returns: available resources types
        :rtype: dict
        """
        response = self.session.get(f"{self.base_url}/resource-types.json")
        decoded_response = json.loads(response.text)
        return decoded_response["body"]

    def get_resource_type_ids(self, per="slug"):
        res = dict()
        for item in self.get_resource_types():
            res[item[per]] = item["id"]
        return res
