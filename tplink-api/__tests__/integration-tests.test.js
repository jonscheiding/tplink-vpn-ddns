import { test as testBase } from 'ava';
import { } from 'dotenv/config';

import { RouterService, ROUTER_CALLS } from '../router-service';
import { encrypt } from '../encrypt';

let test = testBase;
if(!process.env.ROUTER_URL) {
  test = testBase.skip;
}

const service = new RouterService(process.env.ROUTER_URL);

test('can get authentication keys from router', async t => {
  const result = await service.execute(ROUTER_CALLS.GET_AUTHENTICATION_KEYS);
  
  t.true(result instanceof Object);
  t.true(result.data instanceof Object);
  t.true(result.data.password instanceof Array);

  t.is(result.data.username, '');
  t.is(result.data.password.length, 2);
  t.is(result.data.password[0].length, 256);
  t.is(result.data.password[1].length, 6);
});

test('can login with username and password', async t => {
  const keys = await service.execute(ROUTER_CALLS.GET_AUTHENTICATION_KEYS);
  const [ modulus, exponent ] = keys.data.password;

  const username = process.env.ROUTER_USERNAME;
  const password = encrypt(process.env.ROUTER_PASSWORD, { modulus, exponent });

  await t.notThrows(service.execute(ROUTER_CALLS.LOGIN, {username, password}));
});
