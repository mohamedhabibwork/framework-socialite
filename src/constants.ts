/** Constants of `@framework/socialite`: DI tokens and fixed defaults. */
import { token } from '@framework/core';
import type { SocialAccountStore, SocialiteManager } from './types';

/** The social login manager (driver registry). */
export const SOCIALITE_MANAGER = token<SocialiteManager>('socialite.manager');

/** Linked provider identities. */
export const SOCIAL_ACCOUNT_STORE = token<SocialAccountStore>('socialite.account-store');
