  const crypto = require('crypto');
  const pako = require('pako');
  const CryptoJS = require('crypto-js');
  const c25519 = require('../util/curve25519_.js');
  const helpers = require('./helpers');

  function getPrivateKey(secretPhrase) {
    const bytes = helpers.simpleHash(
          helpers.stringToByteArray(secretPhrase)
      );
    const res = c25519.clamp(
          helpers.byteArrayToShortArray(bytes)
      );
    return helpers.shortArrayToHexString(res);
  }

  function getSharedKey(key1, key2) {
    key1 = helpers.byteArrayToShortArray(key1);
    key2 = helpers.byteArrayToShortArray(key2);
    const shared = c25519.curve25519(key1, key2, null);
    return helpers.shortArrayToByteArray(shared);
  }

  function aesDecrypt(ivCiphertext, options) {
    if (ivCiphertext.length < 16 || ivCiphertext.length % 16 !== 0) {
      return false;
    }
    const iv = helpers.byteArrayToWordArray(
          ivCiphertext.slice(0, 16)
      );
    const ciphertext = helpers.byteArrayToWordArray(
          ivCiphertext.slice(16)
      );
    for (let i = 0; i < 32; i++) {
      options.sharedKey[i] ^= options.nonce[i];
    }
    const key = CryptoJS.SHA256(
          helpers.byteArrayToWordArray(options.sharedKey)
      );
    const encrypted = CryptoJS.lib.CipherParams.create({
      ciphertext,
      iv,
      key
    });
    const decrypted = CryptoJS.AES.decrypt(encrypted, key, {
      iv
    });
    return helpers.wordArrayToByteArray(decrypted);
  }

  function aesEncrypt(plaintext, options) {
    const text = helpers.byteArrayToWordArray(plaintext);
    for (let i = 0; i < 32; i++) {
      options.sharedKey[i] ^= options.nonce[i];
    }
    const key = CryptoJS.SHA256(
          helpers.byteArrayToWordArray(options.sharedKey)
      );
    const tmp = crypto.randomBytes(16);
    const iv = helpers.byteArrayToWordArray(tmp);
    const encrypted = CryptoJS.AES.encrypt(text, key, {
      iv
    });
    const ivOut = helpers.wordArrayToByteArray(encrypted.iv);
    const ciphertextOut = helpers.wordArrayToByteArray(encrypted.ciphertext);
    return ivOut.concat(ciphertextOut);
  }

  function decryptMessage(message, nonce, publicKey, secretPhrase) {
    const options = {
      privateKey: helpers.hexStringToByteArray(
              getPrivateKey(secretPhrase)
          ),
      publicKey: helpers.hexStringToByteArray(publicKey),
      nonce: helpers.hexStringToByteArray(nonce)
    };
    options.sharedKey = getSharedKey(options.privateKey, options.publicKey);
    const messageBytes = helpers.hexStringToByteArray(message);
    const compressedPlaintext = aesDecrypt(messageBytes, options);
    if (!compressedPlaintext) {
      return false;
    }
    const binData = new Uint8Array(compressedPlaintext);
    return helpers.byteArrayToString(pako.inflate(binData));
  }

  function encryptMessage(message, publicKey, secretPhrase) {
    const options = {
      privateKey: helpers.hexStringToByteArray(
              getPrivateKey(secretPhrase)
          ),
      publicKey: helpers.hexStringToByteArray(publicKey),
      nonce: crypto.randomBytes(32)
    };
    options.sharedKey = getSharedKey(options.privateKey, options.publicKey);
    const plaintext = helpers.stringToByteArray(message);
    const compressedPlaintext = pako.gzip(
          new Uint8Array(plaintext)
      );
    const encrypted = aesEncrypt(compressedPlaintext, options);
    return {
      message: helpers.byteArrayToHexString(encrypted),
      nonce: helpers.byteArrayToHexString(options.nonce)
    };
  }

  module.exports = {
    decryptMessage,
    encryptMessage
  };
