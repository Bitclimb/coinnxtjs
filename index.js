const NXT = require('./lib');
const assert = require('assert');
const { HDNode } = require('bitcoinjs-lib');
module.exports = class Nxtjs {
  static fromSeedBuffer(seed, coin) {
    const nxtjs = NXT(coin.toUpperCase());
    return new Nxtjs(HDNode.fromSeedBuffer(seed), nxtjs);
  }

  constructor(hdKey, nxtjs) {
    assert(hdKey);
    assert(nxtjs);
    this.key = hdKey;
    this.nxtjs = nxtjs;
  }
  derivePath(p) {
    this.derived = this.key.derivePath(p);
    return this;
  }
  getAddress() {
    let address = this.nxtjs.secretPhraseToAccountId(this.getPrivateKey());
    return address;
  }

  getPrivateKey() {
    const privkey = this.derived.keyPair.d.toBuffer();
    return privkey.toString('hex');
  }
  signTransaction(txhex) {
    return this.nxtjs.signTransactionBytes(txhex, this.getPrivateKey());
  }
};
