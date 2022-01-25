Under active development.  Do not use, yet.

# Turnstile - One Way Encryption #

Turnstile uses public key encryption to allow data to be encrypted in such a way that only a key, 
not-present on the encrypting machine, can be used to decrypt it.

Cryptographically, turnstile is just a wrapper around libsodium's `box`.


## Uses Cases ##

### Logging ###

Piping log output through turnstile causes logs to be readable only after moving them off-box, to
the computer with the private key.  This means that historical logs are protected if a webserver, 
for example, is compromised.

### Encrypting Files ###

If you are given a recipient's public key, you can encrypt data and put it in a public place,
knowing that only they can decrypt it.  (You can't even decrypt it yourself, so you'd better keep
the original, if you need it.) 


## Usage ##

Creating a base62 ed25519 key on the target machine:
```
target:/some/dir $ turnstile keygen
new secret key written into /home/fadedbee/.turnstile/i8q8p2L8gZpZsPD8NRcTiFfQHLfrhoq3IvsaEwWzPJH.secret
```

Encrypt a stream on the source machine:
```
source:/other/dir $ echo "hello world" | turnstile encrypt i8q8p2L8gZpZsPD8NRcTiFfQHLfrhoq3IvsaEwWzPJH > filename.txt.t7e
```

Decrypt a stream on the target machine:
```
target:/some/dir $ cat filename.txt.t7e | turnstile decrypt
hello world
```
(`filename.txt.t7e` contains the target's public key.  Decryption reads the associated secret key from `/home/fadedbee/.turnstile/i8q8p2L8gZpZsPD8NRcTiFfQHLfrhoq3IvsaEwWzPJH.secret`.)


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
| Len |                                         |
+--+--+                                         +
|                                               |
+                  Ciphertext                   +
|                                               |
v                                               v
```
Final Chunk:
```
+--+--+
|00 00|
+--+--+
```


# Design Choices #

Documentation of trade-offs anmd compromises.


## Requiring private keys to be in files (in ~/.turnstile) ##

It would have been possible to put target secret keys on the command line too, rather than
using `~/.turnstile`.  This would be insecure for multi-user machines, as `ps` and `top` show the
command line arguments of other users.


## Using Base62 ##

- Base64 is more common, but needs to be quoted in shell commands and does not cut and paste easily.
- Base58 has guards which might be useful for hand-typing keys, but is longer and variably sized.


## Including the Target Public Key in the Encryption Output ##

There is no need for the target public key to exist in the encryption output.

Pros:
- Allows decryption to only try one secret key, rather than all it knows.
- Users can inspect a .t7e file to find which public key they need to use to decrypt it.

Cons:
- Adds identifiable infomation to the encryption output.


## Using ~/.turnstile rather than Ed25519 SSH keys in ~/.ssh ##

The encryption used by turnstile is compatible with SSH's .ssh/id_ed25519.pub files.

It would have been nice to use pre-existing keys, but:
- We'd need to explain the differences between SSH key types to users.
- Base64 and quoting would have to be used.


## Using a 16-bit Ciphertext Length in Chunks ##

In order to deal with streaming, we must break the input up into chunks, each of which can be
decrypted in turn.  (Decryption includes an integrity check.)

Smaller chunks have more overhead. but allowing larger chunks means more length overhead for each
small chunk. 

We could have used a variably-sized integer for the length, which would have saved some space, at
the expense of some CPU cycles.

For the time-being, we've settled on a maximum chunk size of 65,535 bytes.

For large files, every 65,519 bytes of plaintext results in a chunk containing 2 bytes of length and
65,535 bytes of cipher text.

This is less than a 0.03% overhead.  This is acceptable, given the simplicity of using a u16 for the
chunk length.


## Nonce generation ##

Nonces must not be reused for any given pair of public and secret keys.

Every chunk is encrypted with a different nonce, which is simple an XOR of the initial nonce and the
chunk number.

As each message is encrypted using a different secret key, there is no need for initial nonces to
differ.  But we randomly generate initial nonces and write them into the header, just in case...

