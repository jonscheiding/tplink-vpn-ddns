import  { ROUTER_CALLS } from './router-service';
import { encrypt } from './encrypt';

export class TPLinkRouter {
  constructor(routerService) {
    this.service = routerService;
    this.encrypt = encrypt;
  }

  async login(username, password) {
    const keys = await this.service.execute(ROUTER_CALLS.GET_AUTHENTICATION_KEYS);
    const [ modulus, exponent ] = keys.data.password;

    password = encrypt(password, { modulus, exponent });
  
    const response = await this.service.execute(ROUTER_CALLS.LOGIN, {username, password});

    this.authentication = {
      stok: response.data.stok,
      sysauth: response.cookies.sysauth
    };
  }
}
