from passbolt import PassboltAPI
import json
import sys
import gnupg

# with open("config.json") as config_file:
#    config = json.load(config_file)
#    print(config.get("base_url"))
#
# gpg = gnupg.GPG()
# print(gpg.import_keys(config.get("private_key")).fingerprints[0])
# print()
#
# sys.exit(0)
p = PassboltAPI()
p.get_resources()
resource = next(item for item in p.get_resources() if item["name"] == "Snyk")
res = json.loads(p.decrypt(p.get_resource_secret(resource["id"])).data)

# print password
print(res["password"])
print(resource)
