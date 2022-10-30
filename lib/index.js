/* eslint-disable no-magic-numbers */

'use strict';

/* global Buffer */

const CryptoUtils = require('./crypto-utils');

const YEAR_IN_SECONDS             = 31557600;
const DEFAULT_EXPIRATION_SECONDS  = 2592000;

class TWTError extends Error {}

function nowSeconds() {
  return Math.floor(Date.now() / 1000.0);
}

function createError(message, code, cause) {
  let error = new TWTError(message);
  error.code = code;

  if (cause)
    error.cause = cause;

  return error;
}

function validateEncodedSecret(encodedSecret) {
  if (!encodedSecret)
    throw createError('Bad "encodedSecret" provided: "encodedSecret" must be a URL-safe base64 encoded JSON object containing valid "secretKey" and "iv" properties', 'ESECRET');

  let encodedSecretResult;
  try {
    encodedSecretResult = CryptoUtils.getSaltProperties(encodedSecret);
  } catch (error) {
    throw createError('Bad "encodedSecret" provided: "encodedSecret" must be a URL-safe base64 encoded JSON object containing valid "secretKey" and "iv" properties', 'ESECRET');
  }

  if (!encodedSecretResult.secretKey || !encodedSecretResult.iv)
    throw createError('Bad "encodedSecret" provided: "encodedSecret" must be a URL-safe base64 encoded JSON object containing valid "secretKey" and "iv" properties', 'ESECRET');

  let secretKey = CryptoUtils.fromURLSafeBase64(encodedSecretResult.secretKey);
  if (!Buffer.isBuffer(secretKey) || secretKey.length !== 32)
    throw createError('Bad "encodedSecret" provided: "encodedSecret.secretKey" must be a Buffer with a length of 32 bytes', 'ESECRET');

  let iv = CryptoUtils.fromURLSafeBase64(encodedSecretResult.iv);
  if (!Buffer.isBuffer(iv) || iv.length !== 16)
    throw createError('Bad "encodedSecret" provided: "encodedSecret.iv" must be a Buffer with a length of 16 bytes', 'ESECRET');
}

function validateOptions(now, options) {
  // validAt
  if (typeof options.validAt !== 'number')
    throw createError('"validAt" must be a number (of seconds since the UNIX epoch)', 'EVALIDAT');

  if (options.validAt < now)
    throw createError('"validAt" must be no sooner than "now" in seconds since the UNIX epoch', 'EVALIDAT');

  if (options.validAt > (now + YEAR_IN_SECONDS))
    throw createError('"validAt" can not be more than a year into the future', 'EVALIDAT');

  if (typeof options.expiresAt !== 'number')
    throw createError('"expiresAt" must be a number (of seconds since the UNIX epoch)', 'EEXPIRESAT');

  if (options.expiresAt < now)
    throw createError('"expiresAt" must be no sooner than "now" in seconds since the UNIX epoch', 'EEXPIRESAT');

  if (options.expiresAt < options.validAt)
    throw createError('"expiresAt" must not be before "validAt"', 'EEXPIRESAT');

  if ((options.expiresAt - options.validAt) > YEAR_IN_SECONDS)
    throw createError('"expiresAt" can not be more than a year into the future from "validAt"', 'EEXPIRESAT');

  validateEncodedSecret(options.encodedSecret);
}

function generateTWT(props, _options) {
  let options = Object.assign({}, _options || {});
  let now     = nowSeconds();

  if (!options.validAt)
    options.validAt = now;

  if (!options.expiresAt)
    options.expiresAt = options.validAt + DEFAULT_EXPIRATION_SECONDS;

  validateOptions(now, options);

  let claims = Object.assign(
    {},
    props || {},
    {
      $:  options.validAt.toString(36),
      $$: options.expiresAt.toString(36),
    },
  );

  let serialized;
  try {
    serialized = JSON.stringify(claims);
  } catch (error) {
    throw createError(`Serializing error: ${error.message}`, 'ESERIALIZE', error);
  }

  try {
    return CryptoUtils.encrypt(serialized, options.encodedSecret);
  } catch (error) {
    throw createError(`Encryption error: ${error.message}`, 'EENCRYPTION', error);
  }
}

function verifyTWT(token, _options) {
  let options = (typeof _options === 'string') ? { encodedSecret: _options } : (_options || {});
  let keyMap  = options.keyMap;
  let allowableClockDriftSeconds = (typeof options.allowableClockDriftSeconds === 'number' && isFinite(options.allowableClockDriftSeconds)) ? options.allowableClockDriftSeconds : 120;

  validateEncodedSecret(options.encodedSecret);

  let now = nowSeconds();
  let decrypted;
  let claims;

  try {
    decrypted = CryptoUtils.decrypt(token, options.encodedSecret);
  } catch (error) {
    throw createError(`Decryption error: ${error.message}`, 'EENCRYPTION', error);
  }

  try {
    claims = JSON.parse(decrypted);
    claims.$ = parseInt(claims.$, 36);
    claims.$$ = parseInt(claims.$$, 36);
  } catch (error) {
    throw createError(`Parsing error: ${error.message}`, 'EPARSE', error);
  }

  if (typeof claims.$ !== 'number' || !isFinite(claims.$) || claims.$ <= 0)
    throw createError('Invalid token', 'ETIME');

  if (typeof claims.$$ !== 'number' || !isFinite(claims.$$) || claims.$$ <= 0)
    throw createError('Invalid token', 'ETIME');

  if (claims.$ > claims.$$)
    throw createError('Token "validAt" is greater than "expiresAt"', 'ETIME');

  let validTime = now - claims.$;
  if (validTime < 0 && Math.abs(validTime) > allowableClockDriftSeconds)
    throw createError('Token is not yet valid', 'ETIME');

  let expireTime = claims.$$ - now;
  if (expireTime < 0 && Math.abs(expireTime) > allowableClockDriftSeconds)
    throw createError('Token has expired', 'ETIME');

  claims.expiresIn = claims.$$ - claims.$;

  let mappedClaims  = {};
  let keys          = Object.keys(claims);

  for (let i = 0, il = keys.length; i < il; i++) {
    let key       = keys[i];
    let mappedKey = (keyMap && keyMap[key]) || key;

    if (key === '$')
      mappedKey = 'validAt';

    if (key === '$$')
      mappedKey = 'expiresAt';

    mappedClaims[mappedKey] = claims[key];
  }

  return mappedClaims;
}

const {
  hashToken,
  toURLSafeBase64,
  fromURLSafeBase64,
  getSaltProperties,
  generateSalt,
  encrypt,
  decrypt,
} = CryptoUtils;

module.exports = {
  // crypto-utils
  hashToken,
  toURLSafeBase64,
  fromURLSafeBase64,
  getSaltProperties,
  generateSalt,
  encrypt,
  decrypt,

  // twt
  nowSeconds,
  TWTError,
  generateTWT,
  verifyTWT,
};
