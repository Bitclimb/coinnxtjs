const crypto = require('crypto');
const BigInteger = require('jsbn').BigInteger;
const curve25519 = require('../util/curve25519.js');
const account = require('./account');
const helpers = require('./helpers');

const epochNum = 1385294400;

function createToken(websiteString, secretPhrase) {
  let data = [];
  const hexwebsite = helpers.stringToHexString(websiteString);
  const website = helpers.hexStringToByteArray(hexwebsite);

  const unix = Math.round(+new Date() / 1000);
  const timestamp = unix - epochNum;
  const timestamparray = helpers.intValToByteArray(timestamp);

  data = website.concat(
        account.secretPhraseToPublicKey(secretPhrase, true)
    );
  data = data.concat(timestamparray);

  let token = [];
  token = account.secretPhraseToPublicKey(secretPhrase, true);
  token = token.concat(timestamparray);

  const sig = account.signBytes(data, secretPhrase);
  token = token.concat(sig);

  let buf = '';
  for (let ptr = 0; ptr < 100; ptr += 5) {
    const nbr = [];
    nbr[0] = token[ptr] & 0xFF;
    nbr[1] = token[ptr + 1] & 0xFF;
    nbr[2] = token[ptr + 2] & 0xFF;
    nbr[3] = token[ptr + 3] & 0xFF;
    nbr[4] = token[ptr + 4] & 0xFF;
    const number = helpers.byteArrayToBigInteger(nbr);

    if (number < 32) {
      buf += '0000000';
    } else if (number < 1024) {
      buf += '000000';
    } else if (number < 32768) {
      buf += '00000';
    } else if (number < 1048576) {
      buf += '0000';
    } else if (number < 33554432) {
      buf += '000';
    } else if (number < 1073741824) {
      buf += '00';
    } else if (number < 34359738368) {
      buf += '0';
    }
    buf += number.toString(32);
  }

  return buf;
}

function parseToken(tokenString, website) {
  const websiteBytes = helpers.stringToByteArray(website);
  const tokenBytes = [];
  let i = 0;
  let j = 0;

  for (; i < tokenString.length; i += 8, j += 5) {
    const number = new BigInteger(
            tokenString.substring(i, i + 8),
            32
        );
    const part = helpers.hexStringToByteArray(number.toRadix(16));

    tokenBytes[j] = part[4];
    tokenBytes[j + 1] = part[3];
    tokenBytes[j + 2] = part[2];
    tokenBytes[j + 3] = part[1];
    tokenBytes[j + 4] = part[0];
  }

  if (i != 160) {
    return new Error('tokenString parsed to invalid size');
  }
  let publicKey = [];
  publicKey = tokenBytes.slice(0, 32);
  const timebytes = [
    tokenBytes[32],
    tokenBytes[33],
    tokenBytes[34],
    tokenBytes[35]
  ];

  const timestamp = helpers.byteArrayToIntVal(timebytes);
  const signature = tokenBytes.slice(36, 100);
  const data = websiteBytes.concat(tokenBytes.slice(0, 36));
  const isValid = verifyBytes(signature, data, publicKey);

  const ret = {};
  ret.isValid = isValid;
  ret.timestamp = timestamp;
  ret.publicKey = helpers.byteArrayToHexString(publicKey);
  ret.accountRS = account.publicKeyToAccountId(ret.publicKey);

  return ret;
}

function areByteArraysEqual(bytes1, bytes2) {
  if (bytes1.length !== bytes2.length) {
    return false;
  }
  for (let i = 0; i < bytes1.length; ++i) {
    if (bytes1[i] !== bytes2[i]) {
      return false;
    }
  }
  return true;
}

function verifyBytes(signature, message, publicKey) {
  const v = signature.slice(0, 32);
  const h = signature.slice(32);
  const y = Buffer.from(
        curve25519.verify(v, h, publicKey)
    );
  const m = Buffer.from(
        helpers.simpleHash(message)
    );
  const hash = crypto.createHash('sha256');
  hash.update(m);
  hash.update(y);
  const h2 = hash.digest();
  return areByteArraysEqual(h, h2);
}

module.exports = {
  createToken,
  parseToken
};
