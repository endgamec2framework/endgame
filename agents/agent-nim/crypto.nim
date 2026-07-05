## AES-256-GCM using nimcrypto (pure Nim — no BCrypt dependency).
## Wire format: nonce(12) || ciphertext || tag(16) — matches Go server crypto.go exactly.

import nimcrypto/[bcmode, rijndael]
import winim/lean

const
  NONCE_SIZE* = 12
  TAG_SIZE*   = 16

proc randomBytes*(n: int): seq[byte] =
  result = newSeq[byte](n)
  proc BCryptGenRandom(hAlg: HANDLE; pb: ptr byte; cb, flags: ULONG): LONG
    {.importc, stdcall, dynlib: "bcrypt".}
  discard BCryptGenRandom(0, addr result[0], ULONG(n), 2)

proc sealGCM*(key, plaintext: seq[byte]): seq[byte] =
  ## Encrypt: returns nonce(12) || ciphertext || tag(16)
  let nonce = randomBytes(NONCE_SIZE)
  var ctx: GCM[aes256]
  var k32: array[32, byte]
  var n12: array[12, byte]
  for i in 0 ..< 32: k32[i] = key[i]
  for i in 0 ..< 12: n12[i] = nonce[i]
  ctx.init(k32, n12, [])   # empty AAD
  var ct  = newSeq[byte](plaintext.len)
  if plaintext.len > 0:
    ctx.encrypt(plaintext, ct)
  let tag = ctx.getTag()   # returns array[16, byte]
  result = nonce & ct
  for b in tag: result.add(b)

proc openGCM*(key, data: seq[byte]): seq[byte] =
  ## Decrypt: data = nonce(12) || ciphertext || tag(16)
  if data.len < NONCE_SIZE + TAG_SIZE: return @[]
  let nonce = data[0 ..< NONCE_SIZE]
  let ct    = data[NONCE_SIZE ..< data.len - TAG_SIZE]
  let tag   = data[data.len - TAG_SIZE .. ^1]
  var ctx: GCM[aes256]
  var k32: array[32, byte]
  var n12: array[12, byte]
  for i in 0 ..< 32: k32[i] = key[i]
  for i in 0 ..< 12: n12[i] = nonce[i]
  ctx.init(k32, n12, [])
  var pt = newSeq[byte](ct.len)
  if ct.len > 0:
    ctx.decrypt(ct, pt)
  let computedTag = ctx.getTag()
  for i in 0 ..< 16:
    if computedTag[i] != tag[i]: return @[]
  return pt
