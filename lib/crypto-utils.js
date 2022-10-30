'use strict';

// Useful utilities for cryptography

/* global Buffer */

const Crypto = require('node:crypto');

const URL_SAFE_ENCODING_KEYS  = { '+': '-', '/': '_', '-': '+', '_': '/' };
const ENCRYPTION_ALGORITHM    = 'aes-256-ctr';

function randomBytes(length) {
  let buffer = Buffer.alloc(length);
  Crypto.randomFillSync(buffer);

  return buffer;
}

function sha512(data) {
  let hash = Crypto.createHash('sha512');
  hash.update(data);
  return hash.digest('hex');
}

function toBase64(_data) {
  var data = _data;
  if (data instanceof Uint8Array)
    data = Buffer.from(data);

  if (!Buffer.isBuffer(data))
    data = Buffer.from(('' + _data), 'utf8');

  return data.toString('base64');
}

function convertBase64ToURLSafe(encodedData) {
  return encodedData.replace(/[+/]/g, (m) => {
    return URL_SAFE_ENCODING_KEYS[m];
  });
}

function convertBase64FromURLSafe(encodedData) {
  return encodedData.replace(/[_-]/g, (m) => {
    return URL_SAFE_ENCODING_KEYS[m];
  });
}

function toURLSafeBase64(data) {
  return convertBase64ToURLSafe(toBase64(data));
}

function fromURLSafeBase64(data, encoding) {
  var buffer = Buffer.from(convertBase64FromURLSafe(data), 'base64');
  return (encoding == null) ? buffer : buffer.toString(encoding);
}

function hashToken(token, salt) {
  if (!salt)
    throw new TypeError('Utils::hashToken: "salt" can not be empty');

  return sha512(`${salt}${token}`);
}

function getSaltProperties(salt) {
  let raw   = fromURLSafeBase64(salt, 'utf8');
  let props = JSON.parse(raw);
  return props;
}

function generateSalt() {
  let props = {
    // eslint-disable-next-line no-magic-numbers
    secretKey:  toURLSafeBase64(randomBytes(32)),
    iv:         toURLSafeBase64(randomBytes(16)),
  };

  return toURLSafeBase64(JSON.stringify(props));
}

// secretKey = 32 chars (base64)
// iv = 32 chars (base64)
function encrypt(value, salt) {
  const {
    secretKey,
    iv,
  } = getSaltProperties(salt);

  const cypher    = Crypto.createCipheriv(ENCRYPTION_ALGORITHM, fromURLSafeBase64(secretKey), fromURLSafeBase64(iv));
  const encrypted = Buffer.concat([cypher.update(value), cypher.final()]);

  return toURLSafeBase64(encrypted);
}

function decrypt(value, salt) {
  const {
    secretKey,
    iv,
  } = getSaltProperties(salt);

  const decipher  = Crypto.createDecipheriv(ENCRYPTION_ALGORITHM, fromURLSafeBase64(secretKey), fromURLSafeBase64(iv));
  const decrpyted = Buffer.concat([decipher.update(fromURLSafeBase64(value)), decipher.final()]);

  return decrpyted.toString('utf8');
}

module.exports = {
  hashToken,
  toURLSafeBase64,
  fromURLSafeBase64,
  getSaltProperties,
  generateSalt,
  encrypt,
  decrypt,
};
