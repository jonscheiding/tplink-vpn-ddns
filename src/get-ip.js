/* eslint-disable no-console */

import { } from 'dotenv/config';
import { cleanEnv, str } from 'envalid';

import { TPLinkRouter, RouterService } from './tplink-api';

const env = cleanEnv(process.env, {
  ROUTER_URL: str(),
  ROUTER_USERNAME: str(),
  ROUTER_PASSWORD: str()
});

const router = new TPLinkRouter(
  new RouterService(env.ROUTER_URL)
);

const getPublicIpAddress = async () => {
  await router.login(env.ROUTER_USERNAME, env.ROUTER_PASSWORD);
  const ipInfo = await router.getPublicIpAddress();
  return ipInfo.ipAddress;
};

getPublicIpAddress()
  .then(console.log)
  .catch(console.err);
