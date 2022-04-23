from passbolt import PassboltAPI
from pprint import pprint
import json

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
print("Search for resource 64107118-bc0e-40ff-ae19-2b60c7516e19 (Supabase)")
print("------")
pprint(p.get_resource_per_uuid("64107118-bc0e-40ff-ae19-2b60c7516e19"))
print()

print("Search for the first resource who match the name 'Snyk'")
print("------")

resource = next((item for item in p.get_resources() if item["name"] == "Snyk"), None)
pprint(resource)

if resource is not None:
    # Descrypt Snyk secrets
    res = (
        dict_config.get("gpg_library", "PGPy") == "gnupg"
        and json.loads(p.decrypt(p.get_resource_secret(resource["id"])).data)
        or json.loads(p.decrypt(p.get_resource_secret(resource["id"])))
    )

    print()
    print("Display Snyk password")
    print("------")
    print(res["password"])
    print()
    print("Display Snyk description")
    print("------")
    print(res["description"])
    print()
