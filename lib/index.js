  const account = require('./account');
  const token = require('./token');
  const encryption = require('./encryption');

  module.exports = prefix => {
    process.env.PREFIX = `${prefix}-`;
    return {
      rsConvert: account.rsConvert,
      secretPhraseToPublicKey: account.secretPhraseToPublicKey,
      publicKeyToAccountId: account.publicKeyToAccountId,
      secretPhraseToAccountId: account.secretPhraseToAccountId,
      signTransactionBytes: account.signTransactionBytes,
      createToken: token.createToken,
      parseToken: token.parseToken,
      encryptMessage: encryption.encryptMessage,
      decryptMessage: encryption.decryptMessage
    };
  };
