import request from 'request-promise';
import setCookie from 'set-cookie-parser';
import { URL } from 'url';

export const ROUTER_URL_DEFAULT = 'http://tplinkwifi.net';

export class RouterService {
  constructor(routerUrl = ROUTER_URL_DEFAULT) {
    this.routerUrl = routerUrl;
    this.request = request;
  }

  parseCookies(response) {
    const cookies = {};
    for(let cookie of setCookie.parse(response.headers['set-cookie'])) {
      cookies[cookie.name] = cookie.value;
    }
    return cookies;
  }

  execute(call, parameters, authentication) {
    const { stok, sysauth } = authentication || {};
    const url = new URL(`/cgi-bin/luci/;stok=${stok || ''}${call.path}?form=${call.form}`, this.routerUrl);

    const headers = {};
    if(sysauth) {
      headers['Cookie'] = `sysauth=${sysauth}`;
    }

    const cookieJar = request.jar();

    return this
      .request({
        url: url.toString(),
        headers,
        method: 'POST',
        form: { ...call.parameters, ...parameters },
        resolveWithFullResponse: true,
        jar: cookieJar
      })
      .then(r => ({
        ...JSON.parse(r.body),
        cookies: this.parseCookies(r)
      }))
      .then(r => {
        if (r.success !== true) {
          return Promise.reject(r);
        }
        return r;
      });
  }
}

export class RouterCall {
  constructor(path, form, parameters) {
    this.path = path;
    this.form = form;
    this.parameters = parameters;
  }
}

export const ROUTER_CALLS = {
  GET_AUTHENTICATION_KEYS: new RouterCall('/login', 'cloud_login', {operation: 'read'}),
  LOGIN: new RouterCall('/login', 'cloud_login', {operation: 'login'})
};
