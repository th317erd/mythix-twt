/* eslint-disable no-magic-numbers */

'use strict';

/* global describe, it, expect, fail */

const TWT = require('../lib');

const encodedSecret = 'eyJzZWNyZXRLZXkiOiJmbWxGbXl0SzY5bFJmYl9rLTFsMm9oVG1HSjIyX25KMFdDUWR0YmVUQkRRPSIsIml2IjoieUZ0RHplemhTdFRTbFRwYThGSURTUT09In0=';
const opts = { encodedSecret };

describe('TWT', function() {
  it('should be able to generate and validate TWT', function() {
    let now = TWT.nowSeconds();
    let token = TWT.generateTWT({ u: 'test' }, { ...opts });
    expect(token.length).toEqual(52);

    let claims = TWT.verifyTWT(token, opts);
    expect(claims.u).toEqual('test');
    expect(claims.validAt).toBeInstanceOf(Number);
    expect(Math.abs(claims.validAt - now) < 2).toEqual(true);
    expect(claims.expiresAt - claims.validAt).toEqual(2592000);
  });

  it('should be able to map claim keys', function() {
    let now = TWT.nowSeconds();
    let token = TWT.generateTWT({ u: 'test' }, { ...opts });
    expect(token.length).toEqual(52);

    let claims = TWT.verifyTWT(token, { ...opts, keyMap: { u: 'userID' } });
    expect(claims.userID).toEqual('test');
    expect(claims.validAt).toBeInstanceOf(Number);
    expect(Math.abs(claims.validAt - now) < 2).toEqual(true);
    expect(claims.expiresAt - claims.validAt).toEqual(2592000);
  });

  it('should fail with bad cryptography shenanagins', function() {
    let token = TWT.generateTWT({ u: 'test' }, { ...opts });
    expect(token.length).toEqual(52);

    let badEncodedSecret = TWT.generateSalt();

    try {
      TWT.verifyTWT(token, { encodedSecret: badEncodedSecret });
      fail('unreachable');
    } catch (error) {
      expect(error).toBeInstanceOf(TWT.TWTError);
      expect(error.code).toEqual('EPARSE');
    }

    try {
      TWT.verifyTWT('t' + token, opts);
      fail('unreachable');
    } catch (error) {
      expect(error).toBeInstanceOf(TWT.TWTError);
      expect(error.code).toEqual('EPARSE');
    }

    try {
      TWT.verifyTWT('{"admin":true}', opts);
      fail('unreachable');
    } catch (error) {
      expect(error).toBeInstanceOf(TWT.TWTError);
      expect(error.code).toEqual('EPARSE');
    }
  });

  it('should fail with bad timestamps', function() {
    try {
      TWT.generateTWT({ u: 'test' }, { ...opts, validAt: TWT.nowSeconds() - 1 });
      fail('unreachable');
    } catch (error) {
      expect(error).toBeInstanceOf(TWT.TWTError);
      expect(error.code).toEqual('EVALIDAT');
    }

    try {
      TWT.generateTWT({ u: 'test' }, { ...opts, validAt: TWT.nowSeconds(), expiresAt: TWT.nowSeconds() - 1 });
      fail('unreachable');
    } catch (error) {
      expect(error).toBeInstanceOf(TWT.TWTError);
      expect(error.code).toEqual('EEXPIRESAT');
    }

    try {
      TWT.generateTWT({ u: 'test' }, { ...opts, validAt: TWT.nowSeconds() + 5, expiresAt: TWT.nowSeconds() + 1 });
      fail('unreachable');
    } catch (error) {
      expect(error).toBeInstanceOf(TWT.TWTError);
      expect(error.code).toEqual('EEXPIRESAT');
    }
  });
});
