import { RouterMethod } from './router-method';

export { TPLinkRouter } from './tplink-router';
export { encrypt } from './encrypt';

export { RouterMethod };

export const DEFAULT_URL = 'http://tplinkwifi.net';

export const ROUTER_METHODS = {
  getLoginInfo: new RouterMethod('/login', 'cloud_login', { operation: 'read' }),
  login: new RouterMethod('/login', 'cloud_login', { operation: 'login' })
};
