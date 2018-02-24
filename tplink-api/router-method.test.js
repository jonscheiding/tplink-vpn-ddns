import { test } from 'ava';
const nock = require('nock');

import { TPLinkRouter, Authentication } from './tplink-router';
import { RouterMethod } from './router-method';

const method = new RouterMethod('/testpath', 'testform');
const router = new TPLinkRouter('http://router');

test('makes request to correct url', t => {
  const request = method.createRequest(router);

  t.is(request.url.toString(), 'http://router/cgi-bin/luci;stok=/testpath?form=testform');
});

test('provides authentication when it is available', t => {
  const routerWithAuthentication = new TPLinkRouter(
    router.routerUrl,
    new Authentication('12345', '67890')
  );

  const request = method.createRequest(routerWithAuthentication);

  t.is(request.headers['Cookie'], 'sysauth=12345');
  t.is(request.url.toString(), 'http://router/cgi-bin/luci;stok=67890/testpath?form=testform');
});

test.serial('rejects promise when receiving a non-success status', async t => {
  nock('http://router')
    .filteringPath(() => '/')
    .post('/')
    .reply(500);

  const response = method.execute(router);
  
  await t.throws(response);
});

test.serial('rejects promise when receiving an error indicator in the body', async t => {
  nock('http://router')
    .filteringPath(() => '/').post('/')
    .reply(200, { success: false });

  const response = method.execute(router);

  await t.throws(response);
});
