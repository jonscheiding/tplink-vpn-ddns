import { test } from 'ava';
require('dotenv').config();

import { TPLinkRouter, encrypt, ROUTER_METHODS, DEFAULT_URL } from '..';

const router = new TPLinkRouter(DEFAULT_URL);

test('get encryption info from server', async t => {
  const result = await router.execute(ROUTER_METHODS.getLoginInfo);
  
  t.true(result.success);
  t.is(result.data.username, '');
  t.is(result.data.password.length, 2);
});

test('login to server', async t => { 
  const loginInfo = await router.execute(ROUTER_METHODS.getLoginInfo);
  const [ modulus, exponent ] = loginInfo.data.password;

  const username = process.env.ROUTER_USERNAME;
  const password = encrypt(
    process.env.ROUTER_PASSWORD, 
    { modulus, exponent }
  );

  const result = await router.execute(ROUTER_METHODS.login, { username, password });

  t.true(result.success);
});
