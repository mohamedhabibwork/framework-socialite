import { FrameworkError, type JsonObject } from '@framework/core';
import { createRemoteJWKSet, importPKCS8, type JWTPayload, jwtVerify, SignJWT } from 'jose';
import type { ExchangeInput, RedirectInput, SocialProvider, SocialUser } from './types';

const REQUEST_TIMEOUT_MS = 10_000;
const APPLE_SECRET_LIFETIME = '5m';

/** Declares a provider, for any OAuth 2 or OIDC service the built-in drivers don't cover. */
export const defineSocialDriver = (driver: SocialProvider): SocialProvider => driver;

interface OAuthEndpoints {
  readonly authorize: string;
  readonly token: string;
}

interface OAuthClient {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly scopes?: readonly string[];
}

const failed = (provider: string, step: string): FrameworkError =>
  // Never includes the response: it can echo credentials.
  new FrameworkError('SOCIAL_PROVIDER_FAILED', `${provider} failed during ${step}`);

async function json(provider: string, step: string, response: Response): Promise<JsonObject> {
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok || typeof body !== 'object' || body === null) throw failed(provider, step);
  return body as JsonObject;
}

/** A request the provider's outage or a timeout reports as the provider's fault. */
async function request(provider: string, step: string, url: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(url, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch (cause) {
    throw new FrameworkError('SOCIAL_PROVIDER_FAILED', `${provider} failed during ${step}`, { cause });
  }
}

const authorizeUrl = (
  endpoint: string,
  clientId: string,
  scopes: readonly string[],
  input: RedirectInput,
  extra: Readonly<Record<string, string>> = {},
): string => {
  const url = new URL(endpoint);
  const params = {
    client_id: clientId,
    redirect_uri: input.redirectUri,
    response_type: 'code',
    scope: scopes.join(' '),
    state: input.state,
    ...(input.codeChallenge ? { code_challenge: input.codeChallenge, code_challenge_method: 'S256' } : {}),
    ...extra,
  };
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return url.toString();
};

async function exchange(
  provider: string,
  endpoint: string,
  clientId: string,
  clientSecret: string,
  input: ExchangeInput,
): Promise<{ readonly accessToken: string; readonly idToken?: string }> {
  const response = await request(provider, 'the code exchange', endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      redirect_uri: input.redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
      ...(input.codeVerifier ? { code_verifier: input.codeVerifier } : {}),
    }).toString(),
  });
  const body = await json(provider, 'the code exchange', response);
  if (typeof body.access_token !== 'string') throw failed(provider, 'the code exchange');
  return {
    accessToken: body.access_token,
    ...(typeof body.id_token === 'string' ? { idToken: body.id_token } : {}),
  };
}

const PROFILE_HEADERS = (accessToken: string) => ({
  authorization: `Bearer ${accessToken}`,
  accept: 'application/json',
  'user-agent': 'framework-socialite',
});

const getJson = async (provider: string, url: string, accessToken: string): Promise<JsonObject> =>
  json(
    provider,
    'the profile read',
    await request(provider, 'the profile read', url, { headers: PROFILE_HEADERS(accessToken) }),
  );

const text = (value: unknown): string | null => (typeof value === 'string' && value !== '' ? value : null);

export interface GoogleDriverOptions extends OAuthClient {
  readonly endpoints?: OAuthEndpoints & { readonly user: string };
}

const GOOGLE_ENDPOINTS = {
  authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
  token: 'https://oauth2.googleapis.com/token',
  user: 'https://openidconnect.googleapis.com/v1/userinfo',
};

/** Sign in with Google (OpenID Connect, with PKCE). */
export function googleDriver(options: GoogleDriverOptions): SocialProvider {
  const endpoints = options.endpoints ?? GOOGLE_ENDPOINTS;
  return {
    name: 'google',
    usesPkce: true,
    redirectUrl: (input) =>
      authorizeUrl(endpoints.authorize, options.clientId, options.scopes ?? ['openid', 'email', 'profile'], input),
    exchangeCode: (input) => exchange('google', endpoints.token, options.clientId, options.clientSecret, input),
    async fetchUser(accessToken) {
      const raw = await getJson('google', endpoints.user, accessToken);
      const id = text(raw.sub);
      if (!id) throw failed('google', 'the profile read');
      const email = text(raw.email);
      return {
        id,
        name: text(raw.name) ?? email ?? id,
        email,
        emailVerified: raw.email_verified === true,
        avatarUrl: text(raw.picture),
        raw,
      };
    },
  };
}

export interface GithubDriverOptions extends OAuthClient {
  readonly endpoints?: OAuthEndpoints & { readonly user: string; readonly emails: string };
}

const GITHUB_ENDPOINTS = {
  authorize: 'https://github.com/login/oauth/authorize',
  token: 'https://github.com/login/oauth/access_token',
  user: 'https://api.github.com/user',
  emails: 'https://api.github.com/user/emails',
};

/**
 * Sign in with GitHub. The email comes from `/user/emails`, because the public
 * profile's address is free text the user can set to anything.
 */
export function githubDriver(options: GithubDriverOptions): SocialProvider {
  const endpoints = options.endpoints ?? GITHUB_ENDPOINTS;
  return {
    name: 'github',
    usesPkce: true,
    redirectUrl: (input) =>
      authorizeUrl(endpoints.authorize, options.clientId, options.scopes ?? ['read:user', 'user:email'], input),
    exchangeCode: (input) => exchange('github', endpoints.token, options.clientId, options.clientSecret, input),
    async fetchUser(accessToken) {
      const raw = await getJson('github', endpoints.user, accessToken);
      if (typeof raw.id !== 'number' && typeof raw.id !== 'string') throw failed('github', 'the profile read');
      const response = await request('github', 'the email read', endpoints.emails, {
        headers: PROFILE_HEADERS(accessToken),
      });
      const emails: unknown = response.ok ? await response.json().catch(() => []) : [];
      const primary = (Array.isArray(emails) ? emails : []).find(
        (entry: { readonly primary?: unknown }) => entry?.primary === true,
      ) as { readonly email?: unknown; readonly verified?: unknown } | undefined;
      const id = String(raw.id);
      return {
        id,
        name: text(raw.name) ?? text(raw.login) ?? id,
        email: text(primary?.email),
        emailVerified: primary?.verified === true,
        avatarUrl: text(raw.avatar_url),
        raw,
      };
    },
  };
}

export interface AppleDriverOptions {
  /** The Services ID. */
  readonly clientId: string;
  readonly teamId: string;
  readonly keyId: string;
  /** The `.p8` key's PEM text, or an imported key. */
  readonly privateKey: string | CryptoKey;
  readonly scopes?: readonly string[];
  readonly endpoints?: OAuthEndpoints & { readonly keys: string; readonly issuer: string };
}

const APPLE_ENDPOINTS = {
  authorize: 'https://appleid.apple.com/auth/authorize',
  token: 'https://appleid.apple.com/auth/token',
  keys: 'https://appleid.apple.com/auth/keys',
  issuer: 'https://appleid.apple.com',
};

/**
 * Sign in with Apple. Apple posts the callback back cross-site and identifies the
 * user only through a signed id token, whose name is absent: the id or email stands in.
 */
export function appleDriver(options: AppleDriverOptions): SocialProvider {
  const endpoints = options.endpoints ?? APPLE_ENDPOINTS;
  const keys = createRemoteJWKSet(new URL(endpoints.keys));

  const clientSecret = async (): Promise<string> => {
    const key =
      typeof options.privateKey === 'string' ? await importPKCS8(options.privateKey, 'ES256') : options.privateKey;
    return new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: options.keyId })
      .setIssuer(options.teamId)
      .setSubject(options.clientId)
      .setAudience(endpoints.issuer)
      .setIssuedAt()
      .setExpirationTime(APPLE_SECRET_LIFETIME)
      .sign(key);
  };

  return {
    name: 'apple',
    usesPkce: false,
    responseMode: 'form_post',
    redirectUrl: (input) =>
      authorizeUrl(endpoints.authorize, options.clientId, options.scopes ?? ['name', 'email'], input, {
        response_mode: 'form_post',
      }),
    exchangeCode: async (input) => exchange('apple', endpoints.token, options.clientId, await clientSecret(), input),
    async fetchUser(_accessToken, idToken): Promise<SocialUser> {
      if (!idToken) throw failed('apple', 'the profile read');
      let payload: JWTPayload;
      try {
        ({ payload } = await jwtVerify(idToken, keys, { issuer: endpoints.issuer, audience: options.clientId }));
      } catch (cause) {
        throw new FrameworkError('SOCIAL_PROVIDER_FAILED', 'apple returned an id token that does not verify', {
          cause,
        });
      }
      const id = text(payload.sub);
      if (!id) throw failed('apple', 'the profile read');
      const email = text(payload.email);
      return {
        id,
        name: email ?? id,
        email,
        // Apple sends this as a string or a boolean, depending on the flow.
        emailVerified: payload.email_verified === true || payload.email_verified === 'true',
        avatarUrl: null,
        raw: payload as JsonObject,
      };
    },
  };
}
