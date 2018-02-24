import { URL } from 'url';
const request = require('request-promise');

export class RouterMethod {
  constructor(path, form) {
    this.path = path;
    this.form = form;
  }

  createRequest(router, parameters) {
    const { stok, sysauth } = router.authentication || {};
    const url = new URL(`/cgi-bin/luci;stok=${stok || ''}${this.path}?form=${this.form}`, router.routerUrl);

    return {
      url,
      headers: { 
        'Cookie': `sysauth=${sysauth}`
      },
      method: 'POST',
      form: parameters
    };
  }

  execute(router, parameters) {
    return request(this.createRequest(router, parameters))
      .then(r => {
        if(r.success !== true) {
          return Promise.reject(r);
        }
      });
  }
}
