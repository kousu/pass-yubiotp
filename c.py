from binascii import *

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # pip install cryptography
import crc  # pip install crc


# refs:
# - https://developers.yubico.com/OTP/OTPs_Explained.html
# - https://stackoverflow.com/questions/18594963/crc16-iso-13239-implementation
# - https://reveng.sourceforge.io/crc-catalogue/all.htm#crc.cat.crc-16-ibm-sdlc
#   This one says residue=0xf0b8 which fits with the obscure mention in the 
#   [yubico docs](https://developers.yubico.com/OTP/OTPs_Explained.html) that
#   "This shall give a fixed residual of 0xf0b8 if the checksum is valid. If th"
# https://www.zlib.net/crc_v3.txt
# - https://datatracker.ietf.org/doc/html/rfc1331 (page 61) has an implementatin in C
#   this is based on a lookup-table so, probably not what I ned??
# crc32 in pure shell: https://stackoverflow.com/questions/44804668/how-to-calculate-crc32-checksum-from-a-string-on-linux-bash/55337555#55337555
# crc16, but maybe not the right crc16: https://stackoverflow.com/questions/8564267/crc16-algorithm-from-c-to-bash/58923192#58923192

# endianness in shell: https://stackoverflow.com/questions/22296839/need-a-shell-script-to-convert-big-endian-to-little-endian
# aes in shell: https://stackoverflow.com/questions/16056135/how-to-use-openssl-to-encrypt-decrypt-files

def modhex(s: str):
   # see https://developers.yubico.com/OTP/OTPs_Explained.html
   if isinstance(s, bytes):
     s = s.decode("ascii")
   return s.translate(str.maketrans("abcdef0123456789", "lnrtuvcbdefghijk"))

def unmodhex(s: str):
   # see https://developers.yubico.com/OTP/OTPs_Explained.html
   if isinstance(s, bytes):
     s = s.decode("ascii")
   return s.translate(str.maketrans("lnrtuvcbdefghijk", "abcdef0123456789"))


# a known input-output pair from https://developers.yubico.com/OTP/Specifications/Test_vectors.html

key = "c4422890653076cde73d449b191b416a"
print(f"{key=}")
key = a2b_hex(key)
print(f"{key=}")


private_id = "33c69e7f249e"
print(f"{private_id=}")
use_counter = "0100" # NB: in little-endian
print(f"{use_counter=}")
timestamp = "a71324" # NB: in little-endian
print(f"{timestamp=}")
session_counter = "00"
print(f"{session_counter=}")
random = "3cc6" # NB: in little-endian
print(f"{random=}")
ck = "861c"     # NB: in little-endian
print(f"{ck=}")
ciphertext = "iucvrkjiegbhidrcicvlgrcgkgurhjnj" # aka the One Time Password
print(f"{ciphertext=}")


# configure cryptographic settings

# 1: checksum
# this is defined in https://reveng.sourceforge.io/crc-catalogue/all.htm#crc.cat.crc-16-ibm-sdlc
# but you have to squint at that very terse page to find the parameters.
# I had to confirm some of them experimentally.
IBM = crc.Configuration(width=16, polynomial=0x1021, init_value=0xffff, final_xor_value=0xffff, reverse_input=True, reverse_output=True)

# 2: encryption
# we just need one block of AES; that doesn't exist directly, but setting a null initialization vector in CBC mode is equivalent
aes = Cipher(algorithms.AES(key), modes.CBC(b"\x00"*len(key)))


print()
print("ENCRYPT")

# put together message
plaintext = private_id + use_counter + timestamp + session_counter + random
# compute checksum
digest = crc.Register(IBM)
digest.init()
digest.update(a2b_hex(plaintext))
digest = digest.digest()
# ??? 
print(f"digest={hex(digest)}")
_ck = b2a_hex(digest.to_bytes(2, byteorder='little')).decode("ascii")
print(f"{ck=}")
print(f"{_ck=}")
assert _ck == ck

plaintext = plaintext + _ck
print(f"{plaintext=}")
plaintext = a2b_hex(plaintext)
print(f"{plaintext=}")

# encrypt
_ciphertext = aes.encryptor().update(plaintext)
print(f"{_ciphertext=}")
_ciphertext = b2a_hex(_ciphertext)
print(f"{_ciphertext=}")
_ciphertext = modhex(_ciphertext)
print(f"{_ciphertext=}")




print()
print("DECRYPT")

assert _ciphertext == ciphertext

print(f"{ciphertext=}")
ciphertext = unmodhex(ciphertext)
print(f"{ciphertext=}")
ciphertext = a2b_hex(ciphertext)
print(f"{ciphertext=}")

plaintext = aes.decryptor().update(ciphertext)
print(f"{plaintext=}")

# verify checksum
digest = crc.Register(IBM)
digest.init()
digest.update(plaintext)
digest = digest.digest()
assert ((~digest)&0xFFFF) == 0xf0b8  # verify digest ("16-bit ISO13239 1st complement checksum [...] This shall give a fixed residual of 0xf0b8 if the checksum is valid.")

bPlaintext = plaintext
plaintext = b2a_hex(plaintext)
print(f"{plaintext=}")

print()
print("RE-ENCRYPT")
print(f"{bPlaintext=}")
_ciphertext = aes.encryptor().update(bPlaintext)
print(f"{_ciphertext=}")
_ciphertext = b2a_hex(_ciphertext)
print(f"{_ciphertext=}")
_ciphertext = modhex(_ciphertext)
print(f"{_ciphertext=}")
