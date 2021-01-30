"""
Testing my Algorithms:
test case #1: (msg1, key1) = (b"advanced network security is easy", b"crypto")
test case #2: (msg2, key2) = (b"python is more powerful than c++", b"false")

"""

from sha512 import sha512_
from hashlib import sha512
import hmac
from newhmac import HMAC

# testing SHA-512 algorithm

msg = (b"advanced network security is easy", b"python is more powerful than c++")

print("\nTesting SHA-512 Algorithm...\n")
for i in range(2):
    h = sha512(msg[i]).hexdigest()
    h1 = sha512_(msg[i]).hexdigest()
    if h == h1:
        print("Test case #%s for SHA-512 algorithm passed" % (i+1))
    else:
        print("Error!")

# testing hmac algorithm

key = (b"crypto", b"false")

print("\nTesting Hmac Algorithm...\n")
for i in range(2):
    h = hmac.new(msg[i], key[i], "sha512").hexdigest()
    h1 = HMAC(msg[i], key[i]).hexdigest()
    if h == h1:
        print("Test case #%s for hmac algorithm passed" % (i+1))
    else:
        print("Error!")

