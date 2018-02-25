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

  async getPublicIpAddress() {
    if(!this.authentication) {
      return Promise.reject('Router client is not logged in; please call login() first.');
    }

    const status = await this.service.execute(ROUTER_CALLS.GET_NETWORK_STATUS, {}, this.authentication);
    const detailsCall = this.getDetailsCall(status.data.conntype);

    if(detailsCall === null) {
      return Promise.reject(`Unknown connection type: '${status.data.conntype}'.`);
    }

    const details = await this.service.execute(detailsCall.call, {}, this.authentication);
    const ipInfo = detailsCall.extractIpInfo(details.data);

    return {
      ...ipInfo, connectionType: status.data.conntype
    };
  }

  getDetailsCall(connectionType) {
    switch(connectionType) {
      case 'dhcp': return {
        call: ROUTER_CALLS.GET_NETWORK_DETAILS_DHCP,
        extractIpInfo: data => ({ipAddress: data.ipaddr})
      };
      case 'l2tp': return {
        call: ROUTER_CALLS.GET_NETWORK_DETAILS_L2TP,
        extractIpInfo: data => ({
          ipAddress: data.dyn_ip,
          ipAddressVpn: data.inet_ip
        })
      };
      default: return null;
    }
  }
}
