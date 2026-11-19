import hashlib

known = {
    "jdoe": "e66c883e",
    "rmasri": "b458ae75",
    "tokafor": "973b1f0c",
}

hash_funcs = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

words = [
    "", "reset", "forgot", "meridian", "servicedesk", "salt", "secret",
    "token", "password", "pepper", "key", "auth", "static-salt",
    "meridian-servicedesk", "reset-token", "forgot-password", "changeme",
    "secretkey", "s3cr3t", "123456",
]

def try_formula(name_fn, hash_fn):
    for uname, expected in known.items():
        digest = hash_fn(name_fn(uname).encode()).hexdigest()[:8]
        if digest != expected:
            return False
    return True

found = []
for hname, hfn in hash_funcs.items():
    for w in words:
        # username + word
        if try_formula(lambda u, w=w: u + w, hfn):
            found.append(f"{hname}(username + {w!r})")
        # word + username
        if try_formula(lambda u, w=w: w + u, hfn):
            found.append(f"{hname}(({w!r}) + username)")

if found:
    print("MATCHES FOUND:")
    for f in found:
        print(" -", f)
else:
    print("No match among tried combinations. Showing digests for inspection:")
    for hname, hfn in hash_funcs.items():
        for uname in known:
            print(hname, uname, hfn(uname.encode()).hexdigest()[:8])