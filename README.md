# Computer-Security

## Usage

To run the code -> Open a terminal in directory /java

``` chmod +x build.sh ; chmod +x run.sh ; ./build.sh ; ./run.sh ```

<br>

## Why is it not a good idea to simply encrypt the plaintext with the receiver’s public key? Why bother to generate Key1, IV, and encrypt them?

<br>
In order for the fundamental concept of asymmetric encryption to work, we need a key pair. The only way the keys in the keypair are related is through the fact that you can only decrypt something that was decrypted with either of the keys with the other key. In public key cryptography we use one of these keys to display to the public, so that anyone can decrypt something and send it to use, so that only we can decrypt it when we want to, and vice versa. 
If we were to use only a public key for encryption without an Initialization Vector (IV) we may be exposing too much information about the original ciphertext based on the encrypted message, as without any nonce or IV we will get the same encryption result (specifically this could occur if using ECB mode of operation). The IV is just XOR'ed with the plaintexts first cipher block, before being encrypted.

I suppose it is a good idea to encrypt both values in order for me as a programmer to know that I am the only one that can decrypt them, given the keystore password and alias. It adds another layer of security.

<br>

## Suppose the receiver (i.e. you) does not share any secret with the sender before she/he receives the encrypted keys in ciphertext.enc (i.e. the ciphertext+ the encrypted symmetric keys). Does a verified correct message authentication code (MAC) (e.g. the one received by applying HmacMD5 in this exercise)authenticate the sender or can we trust the origin of the message in this case? Why or why not? (Note that we are assuming that digital signature is not used)

<br>

No it does not verify the sender in this case. Unless a key is shared as a secret between communicating parties, any intercepting party could change the message and recompute the hash to generate a new MAC, and then simply append this new authentication code to the changed message.
