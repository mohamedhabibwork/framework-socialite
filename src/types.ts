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
  readonly clientSecret: string;
  readonly scopes?: readonly string[];
}

/** Validated `socialite` config section. */
export interface SocialiteConfig {
  readonly providers: Readonly<Record<string, SocialProviderConfig>>;
  /** Per-provider redirect URI (absolute or app-relative). */
  readonly redirects: Readonly<Record<string, string>>;
  /** Whether a verified provider email may link to an existing local account. */
  readonly linkByEmail: boolean;
}

/** Facade over the driver registry. */
export interface SocialiteManager {
  driver(name: string): SocialProvider;
  providers(): readonly string[];
}
