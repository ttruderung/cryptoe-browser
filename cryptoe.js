/**
 * Client-size javascript (browser) version of cryptoe, a
 * high-level crypto library providing easy interoperability
 * between client- and server-side environments.
 *
 * @author Tomasz Truderung (ttruderung@gmail.com)
 *
 * Copyright (c) 2015-2017 Tomasz Truderung
 */

var cryptoe = (function() {
cryptoe = {}; // the cryptoe module object

/////// BEGIN OF THE MODULE ///////

//////////////////////////////////////////////////////////////////////
//

function CryptoeError(description) {
  this.name = 'CryptoeError';
  this.message = description || 'Unspecified error';
}
CryptoeError.prototype = Object.create(Error.prototype);
CryptoeError.prototype.constructor = CryptoeError;

cryptoe.Error = CryptoeError;

function assertNumber(x) {
    if (typeof x !== 'number')
        throw new CryptoeError('Type Error: expected number');
}

function assertByte(x) {
    if (typeof x !== 'number' || x<0 || x>255)
        throw new CryptoeError('Type Error: expected byte');
}

function assertMessage(x) {
    if (x.constructor !== newMessage)
        throw new CryptoeError('Type Error: expected message');
}

function assertBytes(x) {
    if (x.length === undefined || typeof x[0] !== 'number')
        throw new CryptoeError('Type Error: expected array of bytes');
}

function assertString(x) {
    if (typeof x !== 'string')
        throw new CryptoeError('Type Error: expected string');
}

function assertHexString(x) {
    if (typeof x !== 'string' || ! /^(([0-9,a-f][0-9,a-f])+$)/.test(x) )
        throw new CryptoeError('Type Error: expected hex sting');
}

//////////////////////////////////////////////////////////////////////
// MESSAGE


/**
 * Private constructor of messages. It creates a messaage  by
 * encapsulating an array of bytes (of type Uint8Array). 
 *
 * @param bytes: (Uint8Array) array of bytes 
 *
 * @param owner: (boolean) specifies if the created message owns the 
 *               underlying buffer (bytes.buffer). If yes, the
 *               message can change the values store in bytes,
 *               otherwise it has to re-allocate before making
 *               any changes.
 *
 * @return a new message object encapsulating 'bytes'
 */
function newMessage(bytes, owner) {
    // Variables bytes (Uint8Array) and owner (boolean) represent the
    // internal state of the created message. 


    // The message object to be returned. All the public methods are
    // added to this object
    var message = Object.create(messageProto);

    message.reallocationCounter = 0; // for testing 
    
    // PUBLIC METHODS OF THE MESSAGE OBJECT

    /**
     * Returns the length of the message.
     */
    message.len = function() { return bytes.length; }

    /**
     * Returns the i-th byte of the message
     */
    message.byteAt = function(n) {
        assertNumber(n);
        return bytes[n];
    }

    /**
     * Returns a slice [begin,end) of the message. If end is unspecified,
     * message.length() is takes as its default value. The argument end
     * can also have negative values, in which case it is relative to the
     * end of the underlying buffer.
     *
     * Slicing is a light-weight operation and does not involve data
     * copying (the underlying data will be, however, copied once one of
     * the append method is called for the returned message).
     */
    message.slice = function(begin, end) {
        if (end===undefined) { end = message.len(); }
        if (end<0) { end = message.len() + end; }
        assertNumber(begin); assertNumber(end);
        return newMessage(bytes.subarray(begin, end), false);
    }

    /**
     * Clones the message. It is a shortcut for slice(0).
     */
    message.clone = function() {
        return message.slice(0);
    }

    /**
     *  Returns the message as an array of bytes (Uint8Array). The
     *  returned array is a copy of the message representation.
     */
    message.toBytes = function() {
        var array = new Uint8Array(message.len()); // create a new array
        array.set(bytes); // and copy the content of bytes to this array
        return array
    }

    /**
     * Returns a string with the hexadecimal representation of the
     * message.
     */
    message.toHexString = function() {
        var hex = "";
        for (var b of bytes) {
            if (b<16) hex += '0';
            hex += b.toString(16);
        }
        return hex;
    }

    /**
     * Returns the base64 representation of the message.
     */
    message.toBase64 = function() {
        // Obtain a string, where every character represents one byte.
        var binstr = String.fromCharCode.apply(null, bytes);
        // Convert it to base54:
        return btoa(binstr);
    }

    /** 
     * Assumes that the message contains a utf-8 encoded string and
     * converts it back to a (native javascript) string. 
     */
    message.toString = function() {
        // Obtain a string, where every character represents one byte.
        var utf8str = String.fromCharCode.apply(null, bytes);
        return decodeURIComponent(escape(utf8str));
    }


    // The following methods read some data from the beginning of
    // the message and move the message forward

    /**
     * Takes a 1-byte signed integer from the beginning of the message,
     * and moves the beginning of the message 1 byte forward.
     */
    message.takeByte = function() {
        if (message.len()<1) throw new CryptoeError("Message.takeByte: not enought data");
        var value = message.byteAt(0);
        message.skip(1);
        return value;
    }

    /**
     * Takes a 2-byte signed integer from the beginning of the message,
     * and moves the beginning of the message 2 byte forward.
     */
    message.takeInt16 = function() {
        if (message.len()<2) throw new CryptoeError("Message.takeInt16: not enought data");
        var value = new DataView(bytes.buffer, bytes.byteOffset).getInt16(0);
        message.skip(2)
        return value;
    }

    /**
     * Takes a 4-byte signed integer from the beginning of the message,
     * and moves the beginning of the message 4 byte forward.
     */
    message.takeInt32 = function() {
        if (message.len()<4) throw new CryptoeError("Message.takeInt32: not enought data");
        var value = new DataView(bytes.buffer, bytes.byteOffset).getInt32(0);
        message.skip(4);
        return value;
    }

    /**
     * Takes a 2-byte unsigned integer from the beginning of the message,
     * and moves the beginning of the message 2 byte forward.
     */
    message.takeUint16 = function() {
        if (message.len()<2) throw new CryptoeError("Message.takeUInt16: not enought data");
        var value = new DataView(bytes.buffer, bytes.byteOffset).getUint16(0);
        message.skip(2);
        return value;
    }

    /**
     * Takes a 4-byte unsigned integer from the beginning of the message,
     * and moves the beginning of the message 4 byte forward.
     */
    message.takeUint32 = function() {
        if (message.len()<4) throw new CryptoeError("Message.takeUint32: not enought data");
        var value = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0);
        message.skip(4);
        return value;
    }

    /**
     * Takes len bytes from the beginning of the messages and returns is
     * as a new message.
     */
    message.takeMessage = function(len) {
        assertNumber(len);
        if (message.len()<len) throw new CryptoeError("Message.takeMessage: not enought data");
        var value = message.slice(0,len);
        message.skip(len);
        return value;
    }

    /**
     * Skips n bytes (moves the beginning of the messages n bytes forward).
     */
    message.skip = function(n) {
        assertNumber(n);
        if (bytes.byteLenght-n < 0) n = bytes.byteLenght;
        bytes = bytes.subarray(n); 
    }


    /**
     * Appends a message msg to this message (does a reallocation, if
     * necessary).
     */
    message.appendMessage = function(msg) {
        assertMessage(msg);
        var end = message.len(); // keep the end, the next line will change it
        var l = msg.len();
        enlargeBy(l); 
        for (var i=0; i<l; ++i) {
            bytes[end++] = msg.byteAt(i);
        }
    }

    /**
     * Appends (an array of) bytes. It accepts anything that
     * has the property bytes.length and can be indexed by bytes[i].
     * Data is copied.
     */
    message.appendBytes = function(bytes) {
        assertBytes(bytes);
        if (bytes.length === undefined) throw new CryptoeError('Message.appendBytes: Type error')
        var len = bytes.length;
        for (var i=0; i<len; ++i) {
            message.appendByte(bytes[i]);
        }
    }

    /**
     * Appends a byte (unsigned 8-bit integer).
     */
    message.appendByte = function(b) {
        assertByte(b);
        var end = message.len();
        enlargeBy(1); 
        bytes[end] = b;
    }

    /**
     * Appends a signed 16-bit integer.
     */
    message.appendInt16 = function(value) {
        assertNumber(value);
        var end = message.len();
        enlargeBy(2); 
        new DataView(bytes.buffer, bytes.byteOffset).setInt16(end, value);
    }

    message.appendUint16 = message.appendInt16;

    /**
     * Appends a signed 16-bit integer.
     */
    message.appendInt32 = function(value) {
        assertNumber(value);
        var end = message.len();
        enlargeBy(4); 
        new DataView(bytes.buffer, bytes.byteOffset).setInt32(end, value)
    }

    message.appendUint32 = message.appendInt32;


    // PRIVATE METHODS

    // Reallocate the byte array to a buffer of size newBufferSize and set
    // the initial size of the array to newArraySize (the array uses
    // part of the buffer; the buffer provides the underlying data).
    //
    function reallocate(newBufferSize, newArraySize) {
        if (newArraySize < message.len() || newBufferSize < newArraySize ) {
            throw new CryptoeError('Message.realocate: wrong size');
        }

        // Allocate a new buffer of size newBufferSize: 
        var newBuffer = new ArrayBuffer(newBufferSize);
        // Create the new array of bytes using elements of buffer from 0 to newArraySize
        var newBytes = new Uint8Array(newBuffer, 0, newArraySize); 
        // Copy existing data from the old array (bytes) to new array (newBytes):
        newBytes.set(bytes); // message.len() bytes is copied
        // Substitute the old array by the new one:
        bytes = newBytes;

        owner = true; // now we own the data
        message.reallocationCounter++;
    }

    // Enlarges the byte array 'bytes' by numberOfNewBytes bytes.
    // If necessary, reallocates the data. Always resizes the byte array 'bytes'.
    //
    function enlargeBy(numberOfNewBytes) {
        var newSize = message.len() + numberOfNewBytes;  // new requested size
        if (!owner ||  // always reallocate if this object does not own the byte array
            bytes.buffer.byteLength < bytes.byteOffset + newSize) // or if there is not enough space
        { 
            // Reallocate:
            var newBufferSize = newSize*2; // twice as much as we need right now
            reallocate(newBufferSize, newSize);
        }
        else { 
            // Resize the array only:
            bytes = new Uint8Array(bytes.buffer, bytes.byteOffset, newSize);
        }
    }

    /**
     * Should not be used outside the module.
     */
    message._rep = function() {
        return bytes;
    }


    // Return the message object
    return message;
}
var messageProto = { constructor: newMessage };
// END OF MESSAGE


/**
 * Creates a new emtpy message.
 */
cryptoe.emptyMessage = function () {
    // We assume that an empty message is created in order to
    // append some data to it. So we set the initial capacity to
    // some non-zero value
    var initialCapacity = 256;
    var buf = new ArrayBuffer(256);
    var bytes = new Uint8Array(buf, 0, 0);
    return newMessage(bytes, true);
}

/**
 * Creates a message from an array of bytes. It accepts anything that
 * has the property bytes.length and can be indexed by bytes[i].
 * Data is copied.
 */
cryptoe.messageFromBytes = function(bytes) {
    assertBytes(bytes);
    if (bytes.length === undefined) throw new CryptoeError('messageFromBytes: Type error')
    var len = bytes.length;
    var arr = new Uint8Array(len);
    for (var i=0; i<len; ++i) {
        arr[i] = bytes[i];
    }
    return newMessage(arr, true);
}

/**
 * Creates a message from a string (in the native javascript encoding). 
 * The returned message is utf-8 encoded.
 */
cryptoe.messageFromString = function (str) {
    assertString(str);
    var binstr = unescape(encodeURIComponent(str)); // each character of utf8str represents one byte
    return messageFromBinString(binstr);
}

/**
 * Returns a message created from a hex-encoded string.
 */
cryptoe.messageFromHexString = function(str) {
    assertHexString(str);
    var len = str.length/2;
    var arr = new Uint8Array(len);
    for (var i=0; i<len; ++i) {
        arr[i] = parseInt(str[2*i], 16)*16 + parseInt(str[2*i+1], 16);
    }
    return newMessage(arr, true);
}

/**
 * Creates a message from a base64 representation.
 */
cryptoe.messageFromBase64 = function(base64str) {
    assertString(base64str);
    try {
        var binstr = atob(base64str); // each character of binstr represents one byte
        return messageFromBinString(binstr);
    } catch (err) {
        throw new CryptoeError("Incorrecty encoded base64 string");
    }
}

// PRIVATE FUNCTIONS

function messageFromBinString(binstr) {
    var len = binstr.length;
    var arr = new Uint8Array(len);
    for (var i=0; i<len; ++i) {
        arr[i] = binstr.charCodeAt(i);
    }
    return newMessage(arr, true);
}

function newMessageFromBuffer(buffer) {
    var bytes = new Uint8Array(buffer);
    return newMessage(bytes, false);
}


//////////////////////////////////////////////////////////////////////
// RANDOM

/**
 * Returns a random message of the given length (in bytes).
 */
cryptoe.random = function(length) {
    if (length===undefined) throw new CryptoeError('random: no lenght given');
    var r = crypto.getRandomValues(new Uint8Array(length));
    return newMessage(r, false);
}

//////////////////////////////////////////////////////////////////////
// HASH
//

/**
 * Returns the hash (SHA-256) of the given message.
 */
cryptoe.hash = function(message) {
    return crypto.subtle.digest("SHA-256", message._rep())
           .then(function (res) {
               return newMessageFromBuffer(res);
           })
           .catch(function (err) {
               throw new CryptoeError('Problems with hashing');
           });
}


//////////////////////////////////////////////////////////////////////
// SYMMETRIC-KEY ENCRYPTION


/**
 * Private constructor for symmetic keys. It encapsuates a
 * cryptoKey object (of web cryptography API).
 */
function newSymmetricKey(cryptoKey) {
    // the key object to be returned
    var key = { _ck:cryptoKey };

    key.encrypt = function (message) {
        // Pick a random IV
        var iv = cryptoe.random(12);
        // Encrypt
        var algo = {name: "AES-GCM", iv: iv._rep(), tagLength: 128};
        return crypto.subtle.encrypt(algo, cryptoKey, message._rep())
               .then(function (raw_result) { 
                    // Now we have the (raw) result of encryption. Prepend this result with the IV:
                    var result = cryptoe.emptyMessage();
                    result.appendMessage(iv);
                    result.appendMessage(newMessageFromBuffer(raw_result))
                    return result;
               });
    }

    key.decrypt = function (message) {
        // Take the iv (first 12 bytes of the message
        var iv = message.takeMessage(12);
        // Decrypt the rest 
        var algo = {name: "AES-GCM", iv: iv._rep(), tagLength: 128};
        return crypto.subtle.decrypt(algo, cryptoKey, message._rep())
               .then(function (res) {
                   return newMessageFromBuffer(res);
               })
               .catch(function (err) {
                   throw new CryptoeError('Invalid ciphertext');
               });
    }

    key.asMessage = function () {
        return crypto.subtle.exportKey('raw', cryptoKey).then(function(rawKey){ 
                    return newMessageFromBuffer(rawKey);  
               });
    }

    // Return the key (this) object
    return key;
};

/**
 * Generate a new symmetic key. 
 *
 * A symmetric key has, most importantly, mehtods 
 * encrypt(m) and decrypt(m).
 */
cryptoe.generateSymmetricKey = function () {
    return crypto.subtle.generateKey({name:"AES-GCM", length:256}, true, ["encrypt", "decrypt"])
           .then(newSymmetricKey);
}

/**
 * Convert a message to a symmetric key.
 */
cryptoe.symmetricKeyFromMessage = function (message) {
    var algo = {name:"AES-GCM", length:128};
    return crypto.subtle.importKey('raw', message._rep().buffer, algo, true, ["encrypt", "decrypt"])
            .then(newSymmetricKey)
            .catch(function (err) {
                throw new CryptoeError('Invalid symmetric key');
            });
}


//////////////////////////////////////////////////////////////////////
// PUBLIC-KEY ENCRYPTION
//

/**
 * Constructor for a decryption (private) key.
 */
function newDecryptionKey(cryptoPrivateKey) {
    // the key object to be returned
    var key = { _ck:cryptoPrivateKey };

    key.decrypt = function (message) {
        return crypto.subtle.decrypt({name: "RSA-OAEP"}, cryptoPrivateKey, message._rep())
               .then(newMessageFromBuffer)
               .catch(function (err) { throw new CryptoeError('Invalid RSA ciphertext'); });
    }

    key.asMessage = function () {
        return crypto.subtle.exportKey('pkcs8', cryptoPrivateKey).then(newMessageFromBuffer);
    }

    // Return the key (this) object
    return key;
};

/**
 * Constructor for an encryption (public) key.
 */
function newEncryptionKey(cryptoPublicKey) {
    // the key object to be returned
    var key = { _ck:cryptoPublicKey };

    key.encrypt = function (message) {
        return crypto.subtle.encrypt({name: "RSA-OAEP"}, cryptoPublicKey, message._rep())
               .then(newMessageFromBuffer)
               .catch(function (err) { throw new CryptoeError('Invalid plaintext (RSA)'); });
    }

    key.asMessage = function () {
        return crypto.subtle.exportKey('spki', cryptoPublicKey).then(newMessageFromBuffer);
    }

    // Return the key (this) object
    return key;
};


/**
 * Generate a new public/private key pair.
 *
 */
cryptoe.generateKeyPair = function () {
    var options = { name:"RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),  // 24 bit representation of 65537
                    hash: {name: "SHA-256"}
               };
    return crypto.subtle.generateKey(options, true, ["encrypt", "decrypt"])
           .then(function (keyPair) {
               return { decryptionKey: newDecryptionKey(keyPair.privateKey),
                        encryptionKey: newEncryptionKey(keyPair.publicKey)};
           });
}

/**
 * Convert a message to an encryption (public) key.
 */
cryptoe.encryptionKeyFromMessage = function (message) {
    var algo = {name:"RSA-OAEP", hash: {name: "SHA-256"}};
    return crypto.subtle.importKey('spki', message._rep().buffer, algo, true, ["encrypt"])
            .then(newEncryptionKey)
            .catch(function (err) {
                throw new CryptoeError('Invalid RSA key');
            });
}

/**
 * Convert a message to a decryption (private) key.
 */
cryptoe.decryptionKeyFromMessage = function (message) {
    var algo = {name:"RSA-OAEP", hash: {name: "SHA-256"}};
    return crypto.subtle.importKey('pkcs8', message._rep().buffer, algo, true, ["decrypt"])
            .then(newDecryptionKey)
            .catch(function (err) {
                throw new CryptoeError('Invalid RSA key');
            });
}

//////////////////////////////////////////////////////////////////////
// DIGITAL SIGNATURES
//

/**
 * Constructor for a verification (public) key.
 */
function newVerificationKey(cryptoVerifKey) {
    var key = {};

    key.verify = function (signature, message) {
        return crypto.subtle.verify({name: "RSASSA-PKCS1-v1_5"}, cryptoVerifKey, signature._rep(), message._rep())
               .catch(function (err) { throw new CryptoeError('Verification error (RSA)'); });
    }

    return key;
};

/**
 * Convert a message to an verification (public) key.
 */
cryptoe.verificationKeyFromMessage = function (message) {
    var algo = {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-256"}};
    return crypto.subtle.importKey("spki", message._rep(), algo, true, ["verify"])
          .then(newVerificationKey)
          .catch(function (err) {
              throw new CryptoeError('Invalid RSA (verification) key');
           });

}

/////// END OF THE MODULE ///////
return cryptoe;
}());

