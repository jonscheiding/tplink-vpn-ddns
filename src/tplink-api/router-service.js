import request from 'request-promise';
import { URL } from 'url';

export const ROUTER_URL_DEFAULT = 'http://tplinkwifi.net';

export class RouterService {
  constructor(routerUrl = ROUTER_URL_DEFAULT) {
    this.routerUrl = new URL('/cgi-bin/luci/', routerUrl);
    this.request = request;
  }

  readCookies(jar) {
    var cookies = {};
    for(let cookie of jar.getCookies(this.routerUrl)) {
      cookies[cookie.key] = cookie.value;
    }
    return cookies;
  }

  execute(call, parameters, authentication) {
    const { stok, sysauth } = authentication || {};
    const url = new URL(`;stok=${stok || ''}${call.path}?form=${call.form}`, this.routerUrl);

    const cookieJar = request.jar();
    if(sysauth) {
      cookieJar.setCookie(`sysauth=${sysauth}`, this.routerUrl);
    }

    return this
      .request({
        url: url.toString(),
        method: 'POST',
        form: { ...call.parameters, ...parameters },
        resolveWithFullResponse: true,
        jar: cookieJar
      })
      .then(r => ({
        ...JSON.parse(r.body),
        cookies: this.readCookies(cookieJar)
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
  LOGIN: new RouterCall('/login', 'cloud_login', {operation: 'login'}),
  GET_NETWORK_STATUS: new RouterCall('/admin/network', 'wan_ipv4_status', {operation: 'read'}),
  GET_NETWORK_DETAILS_DHCP: new RouterCall('/admin/network', 'wan_ipv4_dynamic', {operation: 'read'}),
  GET_NETWORK_DETAILS_L2TP: new RouterCall('/admin/network', 'wan_ipv4_l2tp', {operation: 'read'})
};
