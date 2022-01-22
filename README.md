# Turnstile - a non-return valve for data #

Turnstile uses public key encryption to allow data to be encrypted such that only a key, 
not-present on the encrypting machine, can be used to decrypt it.


## Uses Cases ##

### Logging ###

Piping log output through turnstile means that the log contents can only be read after moving them
off-box, to the location with the private key.  This means that log data is protected if a
webserver, for example, is compromised.

### Encrypting Files ###

If a friend of colleague gives you an ed25519 public key, you can encrypt data and put it in a
public place, knowing that only they can decrypt it.  (You can't even decrypt it yourself, so you
better keep the original, if you need it.) 


## Usage ##

Creating a base62 ed25519 key on the destination machine:
```
destination:/some/dir $ turnstile keygen
public key is AC3NzaC1lZDI1NTE5AIDWSXDSgPPDrZx4PWBBTuCRcmMK
secret key created in ~/.turnstile/AC3NzaC1lZDI1NTE5AIDWSXDSgPPDrZx4PWBBTuCRcmMK.secret
```

Encrypt a file on the source machine:
```
source:/other/dir $ turnstile encrypt AC3NzaC1lZDI1NTE5AIDWSXDSgPPDrZx4PWBBTuCRcmMK filename.txt filename.txt.turnstile
```

Decrypt a file, after copying it to the destination machine:
```
destination:/some/dir $ turnstile decrypt filename.turnstile filename.txt
destination:/some/dir $ cat filename.txt
hello world
```

Encrypt a stream on the source machine:
```
source:/other/dir $ echo "hello world" | turnstile AC3NzaC1lZDI1NTE5AIDWSXDSgPPDrZx4PWBBTuCRcmMK > filename.txt.turnstile
```

Decrypt a stream on the destination machine:
```
destination:/some/dir $ ssh user@source cat /some/dir/filename.turnstile | turnstile --decrypt
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
|            Initial IV             | Reserved  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Blocks:
```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|  Length   |              Tag                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
+                  Ciphertext                   +
|                     ....                      |
.                                               .
```
