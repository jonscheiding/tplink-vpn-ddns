import { test as testBase } from 'ava';
import { } from 'dotenv/config';

import { RouterService } from '../src/tplink-api/router-service';
import { TPLinkRouter } from '../src/tplink-api/tplink-router';

let test = testBase;
if(!process.env.ROUTER_URL) {
  test = testBase.skip;
}

const router = new TPLinkRouter(new RouterService(process.env.ROUTER_URL));

test('can login to router with username and password', async t => {
  await router.login(process.env.ROUTER_USERNAME, process.env.ROUTER_PASSWORD);

  t.true(router.authentication instanceof Object);
  t.is(typeof router.authentication.stok, 'string');
  t.is(typeof router.authentication.sysauth, 'string');
  t.log(router.authentication);
});

test('can get ip address from router', async t => {
  await router.login(process.env.ROUTER_USERNAME, process.env.ROUTER_PASSWORD);
  const ipInfo = await router.getPublicIpAddress();

  t.true(ipInfo instanceof Object);
  t.is(typeof ipInfo.ipAddress, 'string');
  t.is(typeof ipInfo.connectionType, 'string');
  t.log(ipInfo);
});
