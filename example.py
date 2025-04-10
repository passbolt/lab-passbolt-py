from passbolt import PassboltAPI
from pprint import pprint
import json
import pyotp

with open("config.json") as config_file:
    dict_config = json.load(config_file)

p = PassboltAPI(dict_config=dict_config)

print("Creating a new resource and display its id")
print("------")

new_resource = {
    "name": "test-jc-python-api",
    "resource_type_id": p.resource_types["password-and-description"],
    "secrets": [
        {
            "data": p.encrypt(
                {"description": "test", "password": "test"},
                p.get_user_public_key(p.user_id),
            )
        }
    ],
}

r = p.create_resource(new_resource)

# Display new resource id
print("New resource id: {}".format(json.loads(r.text)["body"]["id"]))

print()
print("Search for resource 3c71cf73-52e1-4f55-ba0e-9888f633510c (Supabase)")
print("------")
pprint(p.get_resource_per_uuid("3c71cf73-52e1-4f55-ba0e-9888f633510c"))
print()

print("Search for the first resource who match the name 'Snyk'")
print("------")

resource = next((item for item in p.get_resources() if item["name"] == "hjkl"), None)
pprint(resource)

if resource is not None:
    # Descrypt Snyk secrets
    res = (
        dict_config.get("gpg_library", "PGPy") == "gnupg"
        and json.loads(p.decrypt(p.get_resource_secret(resource["id"])).data)
        or json.loads(p.decrypt(p.get_resource_secret(resource["id"])))
    )

    print()
    print("Display password")
    print("------")
    print(res["password"])
    print()
    print("Display description")
    print("------")
    print(res["description"])
    print()
    if res.get('totp'):
        print("Display totp")
        print("------")
        print(res["totp"])
        secret_key = res['totp']['secret_key']
        digits = res['totp']['digits']
        totp = pyotp.TOTP(
            res['totp']['secret_key'],
            digits=res['totp']['digits']
        )
        print(totp.now())
    print()
