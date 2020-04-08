TweetNacl in Java: port of [tweetnacl-js](https://github.com/dchest/tweetnacl-js)
====================================================================

![Java CI](https://github.com/InstantWebP2P/tweetnacl-java/workflows/Java%20CI/badge.svg)

### API/Usage

### Suggest always use TweetNaclFast implementation

#### Public key authenticated encryption

* get key pair: Box.KeyPair kp = Box.keyPair(), kp = Box.keyPair_fromSecretKey(sk)
* new Box object: Box box = new Box(theirPublicKey, mySecretKey, Nonce);
* encryption: cipher = box.box(message);
* decryption: message = box.open(cipher);
* Nonce MUST be unique for ever message passed between same peers

As an alternative, the nonce can be omitted from the Box() call, and passed in the box and open calls, like:

* byte [] nonce = new byte[nonceLength], randombytes(theNonce, nonceLength);
* Box.KeyPair kp = Box.keyPair(), kp = Box.keyPair_fromSecretKey(sk)
* Box box = new Box(theirPublicKey, mySecretKey);
* encryption: cipher = box.box(message, nonce);
* decryption: message = box.open(cipher, nonce);



#### Secret key authenticated encryption

* get shared key: crypto random, what you have
* new SecretBox object: SecretBox sbox = new SecretBox(sharedKey, Nonce);
* encryption: cipher = sbox.box(message);
* decryption: message = sbox.open(cipher);
* Nonce MUST be unique for ever message passed between same peers

As an alternative, the nonce can be omitted from the SecretBox() call, and passed in the box and open calls, like:

* byte [] nonce = new byte[nonceLength], randombytes(theNonce, nonceLength);
* SecretBox sbox = new SecretBox(sharedKey);
* cipher = sbox.box(message, nonce);
* decryption: message = sbox.open(cipher, nonce);


### Signature

* get key pair: Signature.KeyPair kp = Signature.keyPair(), kp = Signature.keyPair_fromSecretKey(sk);
* new Signature object: Signature sig = new Signature(theirPublicKey, mySecretKey);
* sign: signedMessage = sig.sign(message);
* verify: message = sig.open(signedMessage);
* Nonce MUST be unique for ever message passed between same peers


### Hash

* generate SHA-512: byte [] tag = Hash.sha512(message);


### Refer to com.iwebpp.crypto.tests for details

### About Random generation 

* the library uses java.security.SecureRandom for key generation
* you can always use the library to generate key, or use a Crypto Random like java.security.SecureRandom


### Testing

In top directory:

    $ mvn test


### Support us

* Welcome contributing on document, codes, tests and issues



### License MIT

* Copyright(2014-present) by tom zhou, appnet.link@gmail.com


