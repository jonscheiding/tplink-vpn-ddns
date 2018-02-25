import { test } from 'ava';

import { TPLinkRouter, RouterMethod, DEFAULT_URL } from '.';

const router = new TPLinkRouter(DEFAULT_URL);

test('get encryption info from server', async t => {
  const method = new RouterMethod('/login', 'cloud_login', { operation: 'read' });
  const result = await router.execute(method);
  
  t.true(result.success);
  t.is(result.data.username, '');
  t.is(result.data.password.length, 2);
});
