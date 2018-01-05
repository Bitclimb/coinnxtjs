const crypto = require('crypto');
const BigInteger = require('jsbn').BigInteger;

const charToNibble = {};
const nibbleToChar = [];

let i;
for (i = 0; i <= 9; ++i) {
  const character = i.toString();
  charToNibble[character] = i;
  nibbleToChar.push(character);
}

for (i = 10; i <= 15; ++i) {
  const lowerChar = String.fromCharCode('a'.charCodeAt(0) + i - 10);
  const upperChar = String.fromCharCode('A'.charCodeAt(0) + i - 10);

  charToNibble[lowerChar] = i;
  charToNibble[upperChar] = i;
  nibbleToChar.push(lowerChar);
}

function simpleHash(message, encoding) {
  if (message instanceof Array) {
    message = Buffer.from(message);
  }
  return crypto.createHash('sha256').update(message).digest(encoding);
}

function byteArrayToBigInteger(byteArray, startIndex) {
  let value = new BigInteger('0', 10);
  let temp1, temp2;
  for (let i = byteArray.length - 1; i >= 0; i--) {
    temp1 = value.multiply(new BigInteger('256', 10));
    temp2 = temp1.add(new BigInteger(byteArray[i].toString(10), 10));
    value = temp2;
  }
  return value;
}

function intValToByteArray(number) {
    // We want to represent the input as a 8-bytes array
  const byteArray = [0, 0, 0, 0];
  for (let index = 0; index < byteArray.length; index++) {
    const byte = number & 0xff;
    byteArray[index] = byte;
    long = (number - byte) / 256;
  }
  return byteArray;
}

function byteArrayToIntVal(byteArray) {
    // We want to represent the input as a 8-bytes array
  let intval = 0;
  for (let index = 0; index < byteArray.length; index++) {
    const byt = byteArray[index] & 0xFF;
    const value = byt * Math.pow(256, index);
    intval += value;
  }
  return intval;
}

function hexStringToByteArray(str) {
  const bytes = [];
  let i = 0;
  if (str.length % 2 !== 0) {
    bytes.push(charToNibble[str.charAt(0)]);
    ++i;
  }

  for (; i < str.length - 1; i += 2) {
    bytes.push(
            (charToNibble[str.charAt(i)] << 4) + charToNibble[str.charAt(i + 1)]
        );
  }

  return bytes;
}

function byteArrayToHexString(bytes) {
  let str = '';
  for (let i = 0; i < bytes.length; ++i) {
    if (bytes[i] < 0) {
      bytes[i] += 256;
    }
    str += nibbleToChar[bytes[i] >> 4] + nibbleToChar[bytes[i] & 0x0F];
  }

  return str;
}

function stringToByteArray(str) {
  str = unescape(encodeURIComponent(str));
  const bytes = new Array(str.length);
  for (let i = 0; i < str.length; ++i) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

function stringToHexString(str) {
  return byteArrayToHexString(stringToByteArray(str));
}

function byteArrayToWordArray(byteArray) {
  let i = 0;
  let offset = 0;
  let word = 0;
  const len = byteArray.length;
  const words = new Uint32Array(((len / 4) | 0) + (len % 4 == 0 ? 0 : 1));

  while (i < (len - (len % 4))) {
    words[offset++] = (
            byteArray[i++] << 24) |
        (byteArray[i++] << 16) |
        (byteArray[i++] << 8) |
        (byteArray[i++]);
  }
  if (len % 4 != 0) {
    word = byteArray[i++] << 24;
    if (len % 4 > 1) {
      word = word | byteArray[i++] << 16;
    }
    if (len % 4 > 2) {
      word = word | byteArray[i++] << 8;
    }
    words[offset] = word;
  }
  const wordArray = new Object();
  wordArray.sigBytes = len;
  wordArray.words = words;
  return wordArray;
}

function wordArrayToByteArray(wordArray) {
  const len = wordArray.words.length;
  if (len == 0) {
    return new Array(0);
  }
  const byteArray = new Array(wordArray.sigBytes);
  let offset = 0;
  let word;
  let i;
  for (i = 0; i < len - 1; i++) {
    word = wordArray.words[i];
    byteArray[offset++] = word >> 24;
    byteArray[offset++] = (word >> 16) & 0xff;
    byteArray[offset++] = (word >> 8) & 0xff;
    byteArray[offset++] = word & 0xff;
  }
  word = wordArray.words[len - 1];
  byteArray[offset++] = word >> 24;
  if (wordArray.sigBytes % 4 == 0) {
    byteArray[offset++] = (word >> 16) & 0xff;
    byteArray[offset++] = (word >> 8) & 0xff;
    byteArray[offset++] = word & 0xff;
  }
  if (wordArray.sigBytes % 4 > 1) {
    byteArray[offset++] = (word >> 16) & 0xff;
  }
  if (wordArray.sigBytes % 4 > 2) {
    byteArray[offset++] = (word >> 8) & 0xff;
  }
  return byteArray;
}

function byteArrayToShortArray(byteArray) {
  const shortArray = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  let i;
  for (i = 0; i < 16; i++) {
    shortArray[i] = byteArray[i * 2] | byteArray[i * 2 + 1] << 8;
  }
  return shortArray;
}

function shortArrayToByteArray(shortArray) {
  const byteArray = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  let i;
  for (i = 0; i < 16; i++) {
    byteArray[2 * i] = shortArray[i] & 0xff;
    byteArray[2 * i + 1] = shortArray[i] >> 8;
  }
  return byteArray;
}

function shortArrayToHexString(ary) {
  let res = '';
  for (let i = 0; i < ary.length; i++) {
    res += nibbleToChar[(ary[i] >> 4) & 0x0f] +
        nibbleToChar[ary[i] & 0x0f] +
        nibbleToChar[(ary[i] >> 12) & 0x0f] +
        nibbleToChar[(ary[i] >> 8) & 0x0f];
  }
  return res;
}

function byteArrayToString(bytes, startIndex, length) {
  if (length == 0) {
    return '';
  }
  if (startIndex && length) {
    const index = this.checkBytesToIntInput(
            bytes,
            parseInt(length, 10),
            parseInt(startIndex, 10)
        );
    bytes = bytes.slice(startIndex, startIndex + length);
  }
  return decodeURIComponent(escape(String.fromCharCode.apply(null, bytes)));
}

module.exports = {
  simpleHash,
  byteArrayToBigInteger,
  intValToByteArray,
  byteArrayToIntVal,
  hexStringToByteArray,
  byteArrayToHexString,
  stringToByteArray,
  stringToHexString,
  byteArrayToWordArray,
  wordArrayToByteArray,
  byteArrayToShortArray,
  shortArrayToByteArray,
  shortArrayToHexString,
  byteArrayToString
};
