import { URL } from 'url';
const request = require('request-promise');

export class RouterMethod {
  constructor(path, form, parameters) {
    this.path = path;
    this.form = form;
    this.parameters = parameters;
  }

  createRequest(router, parameters) {
    const { stok, sysauth } = router.authentication || {};
    const url = new URL(`/cgi-bin/luci/;stok=${stok || ''}${this.path}?form=${this.form}`, router.routerUrl);

    const headers = {};
    if(sysauth) {
      headers['Cookie'] = `sysauth=${sysauth}`;
    }

    return {
      url,
      headers,
      method: 'POST',
      form: { ...this.parameters, ...parameters }
    };
  }

  execute(router, parameters) {
    return request(this.createRequest(router, parameters))
      .then(r => JSON.parse(r))
      .then(r => {
        if(r.success !== true) {
          return Promise.reject(r);
        }
        return r;
      });
  }
}
