---
description: A bit of information about Bitcoin addresses
---

# Bitcoin addresses

Addresses (public keys) are generated from the private key using Elliptic Curve Cryptography and are often displayed in Base58 (Base64 with a few confusing characters removed like `0OIl`).&#x20;

You can simulate this behavior if you have a private key for example, but no public key. In this case, simply pass the private key through the normal generating function, here is an example in Python ([source](https://bitcoin.stackexchange.com/a/96191)):

```python
import ecdsa
import hashlib
import base58

private_key = "5JYJWrRd7sbqEzL9KR9dYTGrxyLqZEhPtnCtcvhC5t8ZvWgS9iC"

# WIF to private key by https://en.bitcoin.it/wiki/Wallet_import_format
private_key_bytes = base58.b58decode_check(private_key)[1:]

# Private key to public key (ecdsa transformation)
signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
verifying_key = signing_key.get_verifying_key()
public_key = b"\x04" + verifying_key.to_string()

# hash sha 256 of pubkey
sha256_1 = hashlib.sha256(public_key)

# hash ripemd of sha of pubkey
ripemd160 = hashlib.new("ripemd160")
ripemd160.update(sha256_1.digest())

# checksum
hashed_public_key = b"\x00" + ripemd160.digest()
checksum_full = hashlib.sha256(hashlib.sha256(hashed_public_key).digest()).digest()
checksum = checksum_full[:4]
bin_addr = hashed_public_key + checksum

# encode address to base58 and print
address = base58.b58encode(bin_addr)
print(f"{address=}")  # b'1AsSgrcaWWTdmJBufJiGWB87dmwUf2PLMZ'
```

{% hint style="info" %}
You may have a hex-encoded version of the key. In this case, simply decode the key from hex instead of Base58, and you should have the `private_key_bytes` again
{% endhint %}
