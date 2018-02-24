import { test } from 'ava';

import { encrypt } from './encrypt';

const plainText = 'some_password';

const params = {
  modulus: 
    '8c208030b640d8cc19ae79a728451bcf395c260e14024f7b7251a838b9cbc02a' +
    'ca84e1fce5a56ab95e9b18cd00f52a1153c875e238889e4c6450860fe7a3e346' +
    '6cec6fb3cde02e947553f4c2242e8088986a449427ab66b284d7cdbc95ce25b3' +
    '4302954ed752f182e27a04335c04eff5cd5c92064d04fa0d4179f454ff84cf9f',
  exponent: '010001'
};

const cipherText = 
  '8b15bfa4f908a4c679f2bd6f1a65dd45aee54aec6d767767a9b439f97ca30a05' +
  '5eaa4e609aeb975fbbd70fe25930f39ddb2b5fa60cf3b9abf17c2de49531ded4' +
  'b55943581b600438cb9c97674ad9244505975b326a31a71e2da2df0e256f36fa' +
  'c6aa7bd9742f7f3d8ce4841e6854daa2b065d1e5a3920564848355cca0768d29';

test('encrypt() returns correct text', t => {
  const result = encrypt(plainText, params);
  t.is(result, cipherText);
});
