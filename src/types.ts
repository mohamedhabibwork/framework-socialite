/**
 * Every interface and type of `@framework/socialite` (the Socialite equivalent).
 * Type-only: importing from this module never emits runtime code.
 *
 * Identity is **reused, never duplicated**: drivers normalise a provider user
 * into a `SocialUser`, and `SocialAccountStore` links that identity to the
 * framework-owned `users` row via `@framework/auth`. No second user table.
 */
import type { JsonObject } from '@framework/core';

/** A provider user normalised to the framework's identity model. */
export interface SocialUser {
  /** Provider user id (stable, provider-scoped). */
  readonly id: string;
  readonly name: string;
  readonly email: string | null;
  readonly emailVerified: boolean;
  readonly avatarUrl: string | null;
  readonly raw: JsonObject;
}

/** Input for building a provider authorize redirect URL. */
export interface RedirectInput {
  readonly state: string;
  readonly redirectUri: string;
  /** PKCE challenge, when the driver uses PKCE. */
  readonly codeChallenge?: string;
}

/** Input for exchanging an authorization code for tokens. */
export interface ExchangeInput {
  readonly code: string;
  readonly redirectUri: string;
  readonly codeVerifier?: string;
}

/** One OAuth2/OIDC provider driver (Google, GitHub, …). */
export interface SocialProvider {
  readonly name: string;
  readonly usesPkce: boolean;
  /** `form_post` when the provider posts its callback back, rather than redirecting. */
  readonly responseMode?: 'query' | 'form_post';
  redirectUrl(input: RedirectInput): string;
  exchangeCode(input: ExchangeInput): Promise<{ readonly accessToken: string; readonly idToken?: string }>;
  fetchUser(accessToken: string, idToken?: string): Promise<SocialUser>;
}

/** Links provider identities to framework user ids. Never a second user table. */
export interface SocialAccountStore {
  find(provider: string, providerUserId: string): Promise<{ readonly userId: string } | null>;
  link(provider: string, providerUserId: string, userId: string): Promise<void>;
  unlink(userId: string, provider: string): Promise<boolean>;
}

/** Per-provider credentials and scopes. */
export interface SocialProviderConfig {
  readonly clientId: string;
  /** Required by `google` and `github`. */
  readonly clientSecret?: string;
  readonly scopes?: readonly string[];
  /** `apple` signs its own client secret from these three. */
  readonly teamId?: string;
  readonly keyId?: string;
  readonly privateKey?: string;
}

/** Why a login failed: the fixed code `failureRedirect` receives as `?error=`. */
export type SocialFailure =
  | 'invalid_state'
  | 'provider_denied'
  | 'provider_error'
  | 'email_in_use'
  | 'email_unverified'
  | 'registration_closed'
  | 'already_linked'
  | 'two_step_required';

/** Validated `socialite` config section. */
export interface SocialiteConfig {
  readonly providers: Readonly<Record<string, SocialProviderConfig>>;
  /** Per-provider redirect URI (absolute or app-relative). */
  readonly redirects: Readonly<Record<string, string>>;
  /** Whether an email both the provider and the local account verified may link them. Off by default. */
  readonly linkByEmail: boolean;
  /** Whether a provider identity with a verified email may create a user. */
  readonly registration: boolean;
  /** Where a finished login or link lands; a path on this site. */
  readonly successRedirect: string;
  /** Where a failure lands, with `?error=<SocialFailure>`. */
  readonly failureRedirect: string;
  /** Where a user with two-step login enabled lands, with `#challenge=`. Without it, they can't use social login. */
  readonly twoStepRedirect?: string;
}

/** Facade over the driver registry. */
export interface SocialiteManager {
  driver(name: string): SocialProvider;
  providers(): readonly string[];
}
