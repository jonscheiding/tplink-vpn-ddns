export class Authentication {
  constructor(sysauth, stok) {
    this.sysauth = sysauth;
    this.stok = stok;
  }
}

export class TPLinkRouter {
  constructor(routerUrl, authentication) {
    this.routerUrl = routerUrl;
    this.authentication = authentication;
  }

  execute(method, parameters) {
    return method.execute(this, parameters);
  }
}
