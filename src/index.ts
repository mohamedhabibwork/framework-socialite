// Public API of @framework/socialite.
// Convention: every interface/type lives in `./types`, every constant in
// `./constants`; runtime values (drivers, manager, routes, provider) stay in their modules.
export { SOCIALITE_MANAGER } from './constants';
export type {
  ExchangeInput,
  RedirectInput,
  SocialAccountStore,
  SocialiteConfig,
  SocialiteManager,
  SocialProvider,
  SocialProviderConfig,
  SocialUser,
} from './types';
