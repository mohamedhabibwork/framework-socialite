// Public API of @framework/socialite.
// Convention: every interface/type lives in `./types`, every constant in
// `./constants`; runtime values (drivers, manager, routes, provider) stay in their modules.
export { PgSocialAccountStore } from './account-store';
export { SOCIAL_ACCOUNT_STORE, SOCIALITE_MANAGER } from './constants';
export {
  type AppleDriverOptions,
  appleDriver,
  defineSocialDriver,
  type GithubDriverOptions,
  type GoogleDriverOptions,
  githubDriver,
  googleDriver,
} from './drivers';
export { SocialLogin, type SocialLoginDeps, SocialLoginError } from './login';
export { DriverRegistry } from './manager';
export { createSocialiteProvider, type SocialiteProviderOptions, socialiteConfigSchema } from './provider';
export { type SocialiteRoutesOptions, socialiteRoutes } from './routes';
export { socialAccounts } from './schema';
export type {
  ExchangeInput,
  RedirectInput,
  SocialAccountStore,
  SocialFailure,
  SocialiteConfig,
  SocialiteManager,
  SocialProvider,
  SocialProviderConfig,
  SocialUser,
} from './types';
