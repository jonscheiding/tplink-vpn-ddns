import test from 'ava';
import sinon from 'sinon';
import {} from 'dotenv/config';

import { RouterService } from '../router-service';

const call = { path: '/testpath', form: 'testform' };
const routerUrl = 'http://router';

function spyRequest(body = {}, headers = {}) {
  body = JSON.stringify({ success: true, ...body });
  return sinon.spy(() => Promise.resolve({body, headers}));
}

test('makes request with correct url', async t => {
  const requestSpy = spyRequest();
  const service = new RouterService(routerUrl);
  service.request = requestSpy;

  await service.execute(call);

  sinon.assert.calledWith(requestSpy, sinon.match
    .has('url', 'http://router/cgi-bin/luci/;stok=/testpath?form=testform')
  );

  t.pass();
});

test('makes request with authentication, when provided', async t => {
  const requestSpy = spyRequest();
  const service = new RouterService(routerUrl);
  service.request = requestSpy;

  await service.execute(call, null, {stok: '12345', sysauth: '67890'});

  sinon.assert.calledWith(requestSpy, 
    sinon.match.has('url', 'http://router/cgi-bin/luci/;stok=12345/testpath?form=testform')
      .and(sinon.match.has('headers', 
        sinon.match.has('Cookie', 'sysauth=67890')))
  );

  t.pass();
});

test('includes call parameters when they exist', async t => {
  const requestSpy = spyRequest();
  const service = new RouterService(routerUrl);
  service.request = requestSpy;

  await service.execute({...call, parameters: { callParam: 'callParamValue'} });

  sinon.assert.calledWith(requestSpy, 
    sinon.match.has('form', 
      sinon.match.has('callParam', 'callParamValue')));

  t.pass();
});

test('includes additional execute parameters when they are provided', async t => {
  const requestSpy = spyRequest();
  const service = new RouterService(routerUrl);
  service.request = requestSpy;

  await service.execute(call, {callParam: 'callParamValue'});

  sinon.assert.calledWith(requestSpy, 
    sinon.match.has('form', 
      sinon.match.has('callParam', 'callParamValue')));

  t.pass();
});

test('returns body provided in response', async t => {
  const requestSpy = spyRequest({data: {testData: 'testValue'}});
  const service = new RouterService(routerUrl);
  service.request = requestSpy;

  const response = await service.execute(call, {callParam: 'callParamValue'});

  t.deepEqual(response.data, { testData: 'testValue' });
});

test('returns cookies provided in response', async t => {
  const requestSpy = spyRequest({}, {'set-cookie': 'testCookie=testCookieValue'});
  const service = new RouterService(routerUrl);
  service.request = requestSpy;

  const response = await service.execute(call);

  t.deepEqual(response.cookies, {testCookie: 'testCookieValue'});
});

test('execute parameters override call parameters', async t => {
  const requestSpy = spyRequest();
  const service = new RouterService(routerUrl);
  service.request = requestSpy;

  await service.execute(
    {...call, parameters: {callParam: 'callParamValue1'} }, 
    { callParam: 'callParamValue2'} );

  sinon.assert.calledWith(requestSpy, 
    sinon.match.has('form', 
      sinon.match.has('callParam', 'callParamValue2')));

  t.pass();
});

test('throws if request throws', async t => {
  const requestSpy = sinon.spy(() => Promise.reject({}));
  const service = new RouterService(routerUrl);
  service.request = requestSpy;

  await t.throws(service.execute(call));
});

test('throws if request returns false success', async t => {
  const requestSpy = spyRequest({success: false});
  const service = new RouterService(routerUrl);
  service.request = requestSpy;

  await t.throws(service.execute(call));
});
