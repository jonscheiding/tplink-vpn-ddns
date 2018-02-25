import { test as testBase } from 'ava';
import { } from 'dotenv/config';

import { RouterService } from '../router-service';
import { TPLinkRouter } from '../tplink-router';

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
});
