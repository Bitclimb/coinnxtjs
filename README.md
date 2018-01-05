# coinnxtjs
Simple bip44 derivation of any NXT coin base addresses

## Usage
```js
const nxtjs = require('coinnxtjs');
const bitcoin = require('bitcoinjs-lib');

//using bip39 mnemonic
const seed = bip39.mnemonicToSeed(mnemonic); // your 12 word bip39 seed
// using bip32 xpriv
const seed = bitcoin.crypto.sha256(BIP32_KEY); // your BIP32 KEY

const node = nxtjs.fromSeedBuffer(seed,'BURST');
const master = node.derivePath(`m/44'/60'/0'/0/0`);

console.log(master.getAddress())
//prints BURST-xxxx address
console.log(master.getPrivateKey())
//prints the private seed
master.signTransaction(txhex)
//signs a transaction
```