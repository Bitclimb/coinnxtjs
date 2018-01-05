const crypto = require('crypto');
const curve25519 = require('../util/curve25519');
const NxtAddress = require('../util/nxtaddress');
const helpers = require('./helpers');

function rsConvert(address) {
  const addr = new NxtAddress();
  addr.set(address);
  return {
    account: addr.account_id(),
    accountRS: addr.toString()
  };
}

function secretPhraseToPublicKey(secretPhrase, asByteArray) {
  const hash = helpers.hexStringToByteArray(
        helpers.simpleHash(secretPhrase, 'hex')
    );
  const pubKey = curve25519.keygen(hash).p;
  if (asByteArray) {
    return pubKey;
  }
  return helpers.byteArrayToHexString(pubKey);
}

function publicKeyToAccountId(publicKey, numeric) {
  const arr = helpers.hexStringToByteArray(publicKey);
  const account = helpers.simpleHash(arr, 'hex');

  const slice = (helpers.hexStringToByteArray(account)).slice(0, 8);
  const accountId = helpers.byteArrayToBigInteger(slice).toString();

  if (numeric) {
    return accountId;
  }
  const address = new NxtAddress();
  if (!address.set(accountId)) {
    return '';
  }
  return address.toString();
}

function secretPhraseToAccountId(secretPhrase, numeric) {
  const pubKey = secretPhraseToPublicKey(secretPhrase);
  return publicKeyToAccountId(pubKey, numeric);
}

function signTransactionBytes(data, secretPhrase) {
  const unsignedBytes = helpers.hexStringToByteArray(data);
  const sig = signBytes(unsignedBytes, secretPhrase);

  let signed = unsignedBytes.slice(0, 96);
  signed = signed.concat(sig);
  signed = signed.concat(unsignedBytes.slice(96 + 64));

  return helpers.byteArrayToHexString(signed);
}

function signBytes(message, secretPhrase) {
  const messageBytes = message;
  const secretPhraseBytes = helpers.stringToByteArray(secretPhrase);

  const digest = helpers.simpleHash(secretPhraseBytes);
  const s = curve25519.keygen(digest).s;
  const m = helpers.simpleHash(messageBytes);

  let hash = crypto.createHash('sha256');
  const mBuf = Buffer.from(m);
  const sBuf = Buffer.from(s);
  hash.update(mBuf);
  hash.update(sBuf);
  const x = hash.digest();

  const y = curve25519.keygen(x).p;

  hash = crypto.createHash('sha256');
  const yBuf = Buffer.from(y);
  hash.update(mBuf);
  hash.update(yBuf);
  const h = helpers.hexStringToByteArray(
        hash.digest('hex')
    );

  const v = curve25519.sign(h, x, s);
  return v.concat(h);
}

module.exports = {
  rsConvert,
  secretPhraseToPublicKey,
  publicKeyToAccountId,
  secretPhraseToAccountId,
  signTransactionBytes,
  signBytes
};
