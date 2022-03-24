from passbolt.passbolt import PassboltAPI
from pprint import pprint
import json

p = PassboltAPI()

print()
print("Search for resource 64107118-bc0e-40ff-ae19-2b60c7516e19 (Supabase)")
print("------")
pprint(p.get_resource_per_uuid("64107118-bc0e-40ff-ae19-2b60c7516e19"))
print()

print("Search for the first resource who match the name 'Snyk'")
print("------")

resource = next(item for item in p.get_resources() if item["name"] == "Snyk")
pprint(resource)

# Descrypt Snyk secrets
res = json.loads(p.decrypt(p.get_resource_secret(resource["id"])))

print()
print("Display Snyk password")
print("------")
print(res["password"])
print()
print("Display Snyk description")
print("------")
print(res["description"])
print()
