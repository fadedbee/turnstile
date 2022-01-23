Under active development.  Do not use, yet.

# Turnstile - One Way Encryption #

Turnstile uses public key encryption to allow data to be encrypted in such a way that only a key, 
not-present on the encrypting machine, can be used to decrypt it.

Cryptographically, turnstile is just a wrapper around libsodium's `box`.


## Uses Cases ##

### Logging ###

Piping log output through turnstile means that the log contents can only be read after moving them
off-box, to the location with the private key.  This means that log data is protected if a
webserver, for example, is compromised.

### Encrypting Files ###

If you are given you an ed25519 public key, you can encrypt data and put it in a public place,
knowing that only they can decrypt it.  (You can't even decrypt it yourself, so you'd better keep
the original, if you need it.) 


## Usage ##

Creating a base62 ed25519 key on the target machine:
```
target:/some/dir $ turnstile keygen
public key is AC3NzaC1lZDI1NTE5AIDWSXDSgPPDrZx4PWBBTuCRcmMK
secret key created in ~/.turnstile/AC3NzaC1lZDI1NTE5AIDWSXDSgPPDrZx4PWBBTuCRcmMK.secret
```

Encrypt a file on the source machine:
```
source:/other/dir $ turnstile encrypt AC3NzaC1lZDI1NTE5AIDWSXDSgPPDrZx4PWBBTuCRcmMK -i filename.txt -o filename.txt.t7e
```

Decrypt a file, after copying it to the target machine:
```
target:/some/dir $ turnstile decrypt -i filename.t7e -o filename.txt
target:/some/dir $ cat filename.txt
hello world
```

Encrypt a stream on the source machine:
```
source:/other/dir $ echo "hello world" | turnstile AC3NzaC1lZDI1NTE5AIDWSXDSgPPDrZx4PWBBTuCRcmMK > filename.txt.turnstile
```

Decrypt a stream on the target machine:
```
target:/some/dir $ ssh user@source cat /some/dir/filename.turnstile | turnstile --decrypt
```


## Stream/File Format ##

Header:
```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|FA|DE|DB|EE|t |u |r |n |s |t |i |l |e |Version |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
+            Encryptor's Public Key             +
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
+        Intended Decryptor's Public Key        |
|             (informational only)              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                 Initial Nonce                 |
+                       +--+--+--+--+--+--+--+--+
|                       |
+--+--+--+--+--+--+--+--+
```
Chunks:
```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|        Length         |                       |
+--+--+--+--+--+--+--+--+                       +
|                                               |
+                  Ciphertext                   +
|                                               |
v                                               v
```
Final Chunk:
```
+--+--+--+--+--+--+--+--+
|  0x0000000000000000   |
+--+--+--+--+--+--+--+--+
```


# Design Choices #

These are all the choices made which required compromises.


## Requiring private keys to be in files (in ~/.turnstile) ##

It would have been possible to simply put target private keys on the command line too.  This is
insecure for multi-user machines, as `ps` and `top` would show the private keys of other users.


## Using Base62 ##

- Base64 is more common, but needs to be quoted in shell commands and does not cut and paste easily.
- Base58 has guards which might be useful for hand-typing keys, but is longer and variably lengthed.


## Including the Target Public Key in the Encryption Output ##

There is no need for the target public key to exist in the encryption output.

Pros:
- Allows decryption to only try one secret key, rather than all it knows.
- Users can inspect a .t7e file to find which public key they need to us to decrypt it.

Cons:
- Adds identifiable infomation to the encryption output.


## Using ~/.turnstile rather than Ed25519 SSH keys in ~/.ssh ##

The encryption used by turnstile is compatible with SSH's .ssh/id_ed25519.pub files.

It would have been nice to use pre-existing keys, but:
- We'd need to exlpain the differences between key types.
- Base64 and quoting would have to be used.


## Using a 64-bit Ciphertext Length in Chunks ##

In order to deal with streaming, we must break the input up into chunks, each of which can be
decrypted in turn.  (Decryption includes an integrity check.)

Smaller chunks imply more overhead.

Encrypting a file could be done in one chunk.

We could have used a variably-sized integer for the length, which would have saved some space, at
the expense of some CPU cycles.

