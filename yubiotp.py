from binascii import *
from urllib.parse import *

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # pip install cryptography
import crc  # pip install crc


# configure cryptographic settings

# 1: checksum
# this is defined in https://reveng.sourceforge.io/crc-catalogue/all.htm#crc.cat.crc-16-ibm-sdlc
# but you have to squint at that very terse page to find the parameters.
# I had to confirm some of them experimentally.
IBM = crc.Configuration(width=16, polynomial=0x1021, init_value=0xffff, final_xor_value=0xffff, reverse_input=True, reverse_output=True)


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


def ismodhex(s: str):
   return all(c in "lnrtuvcbdefghijk" for c in s)


def isbase64(s: str):
   return all(c in "0123456789abcdef" for c in s.lower())
  


def generate(secret, public_id, private_id):

  usage_counter = 1
  if session_counter is None or timestamp is None:
    session_counter = 0
    tstp = random.randbytes(3)

  now = time.time()
  return pack(public_id, private_id, usage_counter, session_counter, timestamp), now


# maybe we should encode it as secret,otp,timestamp (in unix time)
def generate_next(secret, otp, prev_timestamp):
  public_id, private_id, usage_counter, session_counter, tstp = unpack(secret, otp)

  now = int(time.time())

  # Decide if we're in the same "session"; this is a bernoulli trial with p=90%
  # and considering sequentual calls makes a geometric distribution with,
  # on average, 1/.9 ~= 1.1 runs in each "session".  Most of the time, sessions
  # last just 1 key long, but sometimes longer, even infinite.
  # (An infinite session is legal, it is what you would get if you left
  # a yubikey in a laptop dock and used it a few times a day.)
  if random.random() > .1:
    # 90% chance of a new session
    # > The timestamp value is set to a random value after startup from the internal random number generator.
    tstp = int.from_bytes(random.randbytes(3), 'little')
    session_counter = 0
  else:
    # 10% chance of staying in the current session
    # > The timestamp is a 24-bit field incremented with a rate of approximately 8 Hz.

    # tstp wraps every 24 days:
    # >>> (2**24)/(8 * 60 * 60 * 24)
    # 24.27259259259259
    # and YubiCo says verifiers just need to be aware of and handle that.
    # (I suspect this means they ignore it)

    ticks = (now - prev_timestamp) * 8
    tstp = (tstp + ticks) & 0xFFFFFF  # tstp+=tickets % 24bits
    session_counter += 1
    session_counter &= 0xFFFF # wrap to 2 bytes
    if session_counter == 0:
      # carry the bit
      usage_counter += 1
      usage_counter &= 0xFF # wrap to 1 byte 

  return pack(secret, public_id, private_id, usage_counter, session_counter, now, rnd), now




def pack(secret, public_id, private_id, usage_counter, session_counter, tstp, rnd=None):
  """
  """

  # TODO: can I figure out what the "use serial" option does?

  # type checking
  # the types are weird, why base64, modhex, base64, int, int, int, bytes?
  # okay maybe i can nitpick that later
  # maybe this is because that's what yubi's generator says

  if not ( isbase64(secret) and len(secret) == (128//8) ):
    raise ValueError("secret must be a 128-bit (16 character) base64 string")

  if not ( ismodhex(public_id) and len(public_id) == 12 ):
    # question: should it be in modhex?
    # how is this generated?
    raise ValueError("public_id must be a 6 byte (12 character) modhex string")

  if not ( isbase64(private_id) and len(public_id) == 12 ):
    raise ValueError("public_id must be a 6 byte (12 character) base64 string")

  if not ( isinstance(usage_counter, int) and 0<usage_counter<2**16 ):
    raise ValueError("usage_counter must be a 16 bit integer")
 
  if not (isinstance(session_counter, int) and 0<session_counter<2**8):
    raise ValueError("If given, session_counter must be a 8 bit integer")

  if not (isinstance(tstp, int) and 0<tstp<2**24):
    raise ValueError("tstp must be a 24 bit integer")

  if rnd is not None and not (isinstance(rnd, bytes) and len(rnd) == 2):
    raise ValueError("If given, rnd must be two bytes")
  
  if rnd is None:
    rnd = random.randbytes(2)

  # ---


  # pack everything to bytes, if it's not already
  # hmmm public_id and private_id
  # what do  Istore them as?
  # they're 

  counter = counter.to_bytes(2, 'little')
  session_counter = session_counter.to_bytes(1, 'little')
  tstp = tstp.to_bytes(3, 'little')

  # > The YubiKey OTP generation is made up of the following fields
  # - https://developers.yubico.com/OTP/OTPs_Explained.html#_the_yubico_otp_generation_algorithm
  plaintext = private_id + counter + timestamp + session_counter + rnd

  # compute checksum
  # > The checksum spans all bytes except the checksum itself.
  digest = crc.Register(IBM)
  digest.init()
  digest.update(plaintext)
  digest = digest.digest()

  digest = digest.to_bytes(2, 'little')
  plaintext += digest

  # check work!
  # verify checksum
  digest = crc.Register(IBM)
  digest.init()
  digest.update(plaintext)
  digest = digest.digest()
  # > 16-bit ISO13239 1st complement checksum [...] This shall give a fixed residual of 0xf0b8 if the checksum is valid."
  # Why the complement? Who knows.
  assert ((~digest)&0xFFFF) == 0xf0b8

  # ^ interesting, this is doing checksum-then-encrypt, when encrypt-then-sign is better
  # i wonder if there's an attack somewhere here

  # > encrypted with a unique AES-128 bit key.
  # - https://developers.yubico.com/OTP/OTPs_Explained.html#_the_yubico_otp_generation_algorithm
  # we just need one block of AES; that doesn't exist directly, but setting a null initialization vector in CBC mode is equivalent
  aes = Cipher(algorithms.AES(secret), modes.CBC(b"\x00"*len(secret)))
  ciphertext = aes.encryptor().update(plaintext)
  ciphertext = b2a_hex(ciphertext)
  ciphertext = modhex(ciphertext)

  # > The result is the 32 character modhex string included after the 12 character public ID.
  # - https://developers.yubico.com/OTP/OTPs_Explained.html#_the_yubico_otp_generation_algorithm
  assert len(ciphertext) == 32
  return public_id + ciphertext

def verify(otp, secret):

def unpack(otp, secret):
  if not ( isinstance(otp, str) and ismodhex(otp) and len(otp) == 44 ):
    raise ValueError("otp should be a 44 character modhex string")
  if not ( isbase64(secret) and len(secret) == 32 ): 
    raise ValueError("secret should be a 128 bit (32 character) base64 string")

  otp = unmodhex(otp)
  otp = a2b_hex(otp)
  public_id, ciphertext = otp[:6], otp[6:]
  # we...ignore public_id
  assert len(ciphertext) == 16

  # we just need one block of AES; that doesn't exist directly, but setting a null initialization vector in CBC mode is equivalent
  aes = Cipher(algorithms.AES(secret), modes.CBC(b"\x00"*len(secret)))
  plaintext = aes.decryptor().update(ciphertext)
  assert len(plaintext) == 16

  plaintext, checksum = plaintext[:-2], plaintext[-2:]
  digest = crc.Register(IBM)
  digest.init()
  digest.update(plaintext)
  digest = digest.digest()
  # > 16-bit ISO13239 1st complement checksum [...] This shall give a fixed residual of 0xf0b8 if the checksum is valid."
  # Why the complement? Who knows.
  if not (  ((~digest)&0xFFFF) == 0xf0b8 ):
    return False

  # split up the rest
  (private_id, counter, timestamp, session_counter, rnd) = (
          plaintext[:6], plaintext[6:8], plaintext[8:11],
	  plaintext[11:12], plaintext[12:14],
	  )

  counter = int.from_bytes(counter, 'little')
  timestamp = int.from_bytes(timestamp, 'little')
  session_counter = int.from_bytes(session_counter, 'little')

  return public_id, private_id, counter, timestamp, session_counter

  # verifying should also:
  # *look* into a database to dig out the record matching public_id
  # and 1. check that secert_id is a match
  #     2. check that counter << 8 + session_counter > previously known counter
  #     3. write counter, session_counter back to the database
  # ...but then I need to manage a database

  return True
  


FIELDS = {'public_id', 'secret', 'private_id', 'counter'}

def yubiparse(u):
  """
  """
  u = urlparse(u)
  if not ( u.scheme == 'yubiotp' and u.netloc == 'yubi' ):
    raise ValueError("Not a yubiotp:// URL")
  s = parse_qs(u.query)
  # either I could just increment the usage counter each time and always set , 
  # MVP: ignore the timestamp and session counter
  if not ( set(s.keys()) == set(FIELDS) ) and all(len(s[k]) == 1 for k in FIELDS):
    raise ValueError("yubiotp URL needs one each of public_id, secret, private_id and counter, e.g. yubiotp://yubi/?public_id=cccjgjgkhcbb&secret=000102030405060708090a0b0c0d0e0f&private_id=010203040506&counter=79")
  return {k: s[k][0] for k in FIELDS}

def yubiunparse(public_id, secret, private_id, counter):
  # TODO: type-check that the params are the right lengths and types
  query = {'public_id': public_id, 'secret': secret, 'private_id': private_id, 'counter': counter}
  u = ParseResult('yubiotp', 'yubi', "", "", urlencode(query), "")
  return urlunparse(u)
  

TESTS = [
  # adapted from https://developers.yubico.com/OTP/Specifications/Test_vectors.html
  ('yubiotp://yubi/?public_id=cccjgjgkhcbb&secret=000102030405060708090a0b0c0d0e0f&private_id=010203040506&counter=0', 'dvgtiblfkbgturecfllberrvkinnctnn'),
  ('yubiotp://yubi?secret=88888888888888888888888888888888&public_id=cccjgjgkhcbb&counter=88&private_id=888888888888', 'dcihgvrhjeucvrinhdfddbjhfjftjdei'),
  ('yubiotp://yubi?counter=1&secret=c4422890653076cde73d449b191b416a&public_id=cccjgjgkhcbb&private_id=33c69e7f249e', 'iucvrkjiegbhidrcicvlgrcgkgurhjnj'),
]

if __name__ == '__main__':
  from pprint import pprint
  for k,o in TESTS:
    pprint(k)
    u = yubiparse(k)
    pprint(u)
    q = yubiunparse(**u)
    pprint(q)
    print()


