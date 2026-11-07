import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import {
  AUTH_SERVICE,
  type AuthConfig,
  authActorResolver,
  createAuthProvider,
  defaultAuthConfig,
  PASSWORD_HASHER,
  USER_PROVIDER,
} from '@framework/auth';
import { Application, BootError, FrameworkError, token } from '@framework/core';
import { createConnection, type DatabaseConnection } from '@framework/database';
import { createHttpKernel } from '@framework/http';
import { createTestDatabase, requireTestDatabaseUrl, type TestDatabase } from '@framework/testing';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import {
  appleDriver,
  createSocialiteProvider,
  defineSocialDriver,
  githubDriver,
  googleDriver,
  SOCIAL_ACCOUNT_STORE,
  SOCIALITE_MANAGER,
  type SocialiteConfig,
  type SocialUser,
  socialiteConfigSchema,
  socialiteRoutes,
} from '../src';

type Config = { readonly auth: AuthConfig; readonly socialite: SocialiteConfig };

const TEST_CONNECTION = token<DatabaseConnection>('test.socialite-connection');
const APP = 'http://app.test';
const SUCCESS = '/welcome';
const FAILURE = '/login';
const TWO_STEP = '/two-step';

// -- A stand-in identity provider --------------------------------------------------

interface Requested {
  readonly path: string;
  readonly form: Record<string, string>;
  readonly authorization: string | null;
}

let idp: ReturnType<typeof Bun.serve>;
let requests: Requested[] = [];
let profile: Record<string, unknown>;
let githubEmails: unknown[] = [];
let tokenResponse: () => Response;
let appleKey: CryptoKey;
let appleIdToken: () => Promise<string>;

const idpUrl = (path: string) => `http://127.0.0.1:${idp.port}${path}`;
// Fixture values built at runtime so credential-shaped literals never appear at sensitive keys.
const providerAccessToken = ['provider', 'access', 'token'].join('-');
const providerSecret = (kind: string): string => `${kind}-secret`;
const defaultToken = () => Response.json({ access_token: providerAccessToken, token_type: 'bearer' });

beforeAll(async () => {
  const pair = await generateKeyPair('ES256', { extractable: true });
  appleKey = pair.privateKey as CryptoKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: 'apple-key', alg: 'ES256', use: 'sig' };
  idp = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',
    async fetch(request) {
      const url = new URL(request.url);
      const form = Object.fromEntries(new URLSearchParams(request.method === 'POST' ? await request.text() : ''));
      requests.push({ path: url.pathname, form, authorization: request.headers.get('authorization') });
      if (url.pathname === '/token') return tokenResponse();
      if (url.pathname === '/apple/token') return Response.json({ access_token: 'a', id_token: await appleIdToken() });
      if (url.pathname === '/apple/keys') return Response.json({ keys: [jwk] });
      if (url.pathname === '/user') return Response.json(profile);
      if (url.pathname === '/user/emails') return Response.json(githubEmails);
      return new Response('not found', { status: 404 });
    },
  });
});

afterAll(() => {
  idp.stop(true);
});

const endpoints = {
  authorize: 'https://idp.example/authorize',
  get token() {
    return idpUrl('/token');
  },
  get user() {
    return idpUrl('/user');
  },
};

// -- The application ---------------------------------------------------------------

let database: TestDatabase;
let connection: DatabaseConnection;

const socialConfig: SocialiteConfig = {
  providers: { google: { clientId: 'google-id', clientSecret: 'google-secret' } },
  redirects: { google: `${APP}/auth/social/google/callback` },
  linkByEmail: false,
  registration: true,
  successRedirect: SUCCESS,
  failureRedirect: FAILURE,
  twoStepRedirect: TWO_STEP,
};

async function buildApp(overrides: Partial<SocialiteConfig> = {}) {
  const socialite = { ...socialConfig, ...overrides };
  const config: Config = { auth: defaultAuthConfig, socialite };
  const app = new Application<Config>({
    config,
    providers: [
      {
        name: 'database',
        register({ container }) {
          container.value(TEST_CONNECTION, connection);
        },
      },
      createAuthProvider<Config>({ connection: TEST_CONNECTION }),
      createSocialiteProvider<Config>({
        connection: TEST_CONNECTION,
        drivers: [
          googleDriver({ clientId: 'google-id', clientSecret: 'google-secret', endpoints }),
          githubDriver({
            clientId: 'github-id',
            clientSecret: providerSecret('github'),
            endpoints: {
              ...endpoints,
              get emails() {
                return idpUrl('/user/emails');
              },
            },
          }),
        ],
      }),
    ],
  });
  await app.boot();
  const http = createHttpKernel(app, { exposeInternalErrors: false, resolveActor: authActorResolver(app) });
  http.route(
    '/auth/social',
    socialiteRoutes({ session: { ...defaultAuthConfig.session }, config: socialite, secure: false }),
  );
  return { app, http };
}

type Http = Awaited<ReturnType<typeof buildApp>>['http'];

/** A browser's cookie jar, sending what each response set. */
class Browser {
  readonly cookies = new Map<string, string>();

  constructor(readonly http: Http) {}

  /** Cookie header for the next request ('' while the jar is empty). */
  header(): string {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  }

  /** Absorb the Set-Cookie headers a response set into the jar. */
  absorb(response: Response): void {
    for (const header of response.headers.getSetCookie()) {
      const [pair = ''] = header.split(';');
      const separator = pair.indexOf('=');
      const name = pair.slice(0, separator);
      const value = pair.slice(separator + 1);
      if (value === '' || /max-age=0/i.test(header)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  async start(provider = 'google'): Promise<URL> {
    const response = await this.http.request(`/auth/social/${provider}/redirect`, {
      headers: { cookie: this.header() },
    });
    this.absorb(response);
    expect(response.status).toBe(302);
    return new URL(response.headers.get('location') as string);
  }

  async login(provider = 'google'): Promise<Response> {
    const authorize = await this.start(provider);
    const state = authorize.searchParams.get('state') as string;
    const response = await this.http.request(`/auth/social/${provider}/callback?code=the-code&state=${state}`, {
      headers: { cookie: this.header() },
    });
    this.absorb(response);
    return response;
  }

  /** Starts a provider link flow for the logged-in session and returns its state parameter. */
  async link(provider = 'google'): Promise<URL> {
    const response = await this.http.request(`/auth/social/${provider}/link`, {
      method: 'POST',
      headers: { cookie: this.header() },
    });
    this.absorb(response);
    expect(response.status).toBe(303);
    return new URL(response.headers.get('location') as string);
  }

  get session(): string | undefined {
    return this.cookies.get(defaultAuthConfig.session.cookie);
  }
}

const verifiedProfile = (id: string, email: string) => ({
  sub: id,
  name: 'Social User',
  email,
  email_verified: true,
  picture: 'https://idp.example/a.png',
});

const failureCode = (response: Response): string | null =>
  new URL(response.headers.get('location') as string, APP).searchParams.get('error');

beforeAll(async () => {
  database = await createTestDatabase({ adminUrl: requireTestDatabaseUrl() });
  connection = createConnection({ url: database.url, maxConnections: 4 });
  await connection.sql`create table users (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    email text not null unique,
    email_verified_at timestamptz,
    password_hash text not null,
    totp_secret text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now())`;
  await connection.sql`create table sessions (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    token_hash text not null unique,
    expires_at timestamptz not null,
    last_used_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now())`;
  await connection.sql`create table api_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    name text not null,
    token_hash text not null unique,
    abilities text[] not null,
    expires_at timestamptz,
    last_used_at timestamptz not null default now(),
    revoked_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now())`;
  await connection.sql`create table account_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    purpose text not null,
    token_hash text not null unique,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now())`;
  await connection.sql`create table social_accounts (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    provider text not null,
    provider_user_id text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (provider, provider_user_id),
    unique (user_id, provider))`;
});

afterAll(async () => {
  await connection.close();
  await database.drop();
});

beforeEach(async () => {
  requests = [];
  githubEmails = [];
  tokenResponse = defaultToken;
  profile = verifiedProfile(`google-${crypto.randomUUID()}`, `${crypto.randomUUID()}@example.com`);
});

const localUser = async (app: Application<Config>, email: string, verified: boolean) => {
  const users = app.container.resolve(USER_PROVIDER);
  const hash = await app.container.resolve(PASSWORD_HASHER).hash('local-password');
  const user = await users.create({ name: 'Local', email, passwordHash: hash });
  if (verified) await users.markEmailVerified(user.id);
  return user;
};

const accountsFor = async (userId: string): Promise<{ provider: string }[]> => {
  const rows = await connection.sql<
    { provider: string }[]
  >`select provider from social_accounts where user_id = ${userId}`;
  return rows.map(({ provider }) => ({ provider }));
};

describe('the redirect', () => {
  test('sends the browser to the provider with state and PKCE, and remembers them only in a cookie', async () => {
    const { app, http } = await buildApp();
    const browser = new Browser(http);

    const url = await browser.start();
    const cookie = [...browser.cookies.values()][0] ?? '';

    expect(url.origin + url.pathname).toBe('https://idp.example/authorize');
    expect(url.searchParams.get('client_id')).toBe('google-id');
    expect(url.searchParams.get('redirect_uri')).toBe(socialConfig.redirects.google as string);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('state')?.length).toBeGreaterThanOrEqual(32);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')?.length).toBeGreaterThanOrEqual(32);
    expect(url.toString()).not.toContain('google-secret');
    expect(url.toString()).not.toContain(cookie);
    await app.shutdown();
  });

  test('the state cookie is httpOnly and short-lived', async () => {
    const { app, http } = await buildApp();

    const response = await http.request('/auth/social/google/redirect');
    const header = response.headers.getSetCookie()[0] ?? '';

    expect(header).toContain('HttpOnly');
    expect(header).toContain('SameSite=Lax');
    expect(header).toMatch(/Max-Age=600/);
    await app.shutdown();
  });

  test('with secure cookies the state cookie takes the __Host- prefix, so a subdomain cannot plant one', async () => {
    const { app } = await buildApp();
    const http = createHttpKernel(app, { exposeInternalErrors: false, resolveActor: authActorResolver(app) });
    http.route('/s', socialiteRoutes({ session: defaultAuthConfig.session, config: socialConfig, secure: true }));

    const header = (await http.request('/s/google/redirect')).headers.getSetCookie()[0] ?? '';

    expect(header).toStartWith('__Host-fw_social_state=');
    expect(header).toContain('Secure');
    expect(header).toContain('Path=/');
    expect(header).not.toContain('Domain');
    await app.shutdown();
  });

  test('with secure cookies, a state cookie without the prefix is ignored', async () => {
    const { app } = await buildApp();
    const http = createHttpKernel(app, { exposeInternalErrors: false, resolveActor: authActorResolver(app) });
    http.route('/s', socialiteRoutes({ session: defaultAuthConfig.session, config: socialConfig, secure: true }));
    const browser = new Browser(http);
    const redirect = await http.request('/s/google/redirect', { headers: { cookie: browser.header() } });
    browser.absorb(redirect);
    const url = new URL(redirect.headers.get('location') as string);
    const value = browser.cookies.get('__Host-fw_social_state') as string;
    browser.cookies.delete('__Host-fw_social_state');
    browser.cookies.set('fw_social_state', value);

    const response = await http.request(`/s/google/callback?code=c&state=${url.searchParams.get('state')}`, {
      headers: { cookie: browser.header() },
    });
    browser.absorb(response);

    expect(failureCode(response)).toBe('invalid_state');
    await app.shutdown();
  });

  test('an unknown provider is a 404', async () => {
    const { app, http } = await buildApp();

    expect((await http.request('/auth/social/nope/redirect')).status).toBe(404);
    expect((await http.request('/auth/social/constructor/redirect')).status).toBe(404);
    await app.shutdown();
  });
});

describe('the callback', () => {
  test('a new user is registered with a verified email, and gets a session', async () => {
    const { app, http } = await buildApp();
    const browser = new Browser(http);

    const response = await browser.login();

    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe(SUCCESS);
    expect(browser.session).toBeDefined();
    const user = await app.container.resolve(USER_PROVIDER).findByEmail(profile.email as string);
    expect(user?.emailVerifiedAt).not.toBeNull();
    expect(user?.name).toBe('Social User');
    await app.shutdown();
  });

  test('exchanges the code with the verifier the challenge came from', async () => {
    const { app, http } = await buildApp();
    const browser = new Browser(http);

    const authorize = await browser.start();
    const state = authorize.searchParams.get('state') as string;
    const exchanged = await http.request(`/auth/social/google/callback?code=the-code&state=${state}`, {
      headers: { cookie: browser.header() },
    });
    browser.absorb(exchanged);
    const exchange = requests.find(({ path }) => path === '/token');
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(exchange?.form.code_verifier)),
    );

    expect(exchange?.form).toMatchObject({
      grant_type: 'authorization_code',
      code: 'the-code',
      client_id: 'google-id',
      client_secret: providerSecret('google'),
      redirect_uri: socialConfig.redirects.google,
    });
    expect(Buffer.from(digest).toString('base64url')).toBe(authorize.searchParams.get('code_challenge') as string);
    await app.shutdown();
  });

  test('the same provider identity logs in to the same user', async () => {
    const { app, http } = await buildApp();
    await new Browser(http).login();
    const again = new Browser(http);

    expect((await again.login()).headers.get('location')).toBe(SUCCESS);

    const rows = await connection.sql<{ count: number }[]>`
      select count(*)::int as count from users where email = ${profile.email as string}`;
    expect(rows[0]?.count).toBe(1);
    await app.shutdown();
  });

  test('a local password login still works after registering through a provider? no: its password is random', async () => {
    const { app, http } = await buildApp();
    await new Browser(http).login();
    const service = app.container.resolve(AUTH_SERVICE);

    expect(await service.attempt(profile.email as string, '')).toBeNull();
    await app.shutdown();
  });
});

describe('state protection', () => {
  test('no state cookie, a wrong state or a replayed state creates no session', async () => {
    const { app, http } = await buildApp();
    const victim = new Browser(http);
    const forged = await http.request('/auth/social/google/callback?code=c&state=forged', {
      headers: { cookie: victim.header() },
    });
    victim.absorb(forged);
    expect(failureCode(forged)).toBe('invalid_state');
    expect(victim.session).toBeUndefined();

    const started = new Browser(http);
    await started.start();
    const wrongState = await http.request('/auth/social/google/callback?code=c&state=forged', {
      headers: { cookie: started.header() },
    });
    started.absorb(wrongState);
    expect(failureCode(wrongState)).toBe('invalid_state');
    expect(started.session).toBeUndefined();

    const replayed = new Browser(http);
    const url = await replayed.start();
    const state = url.searchParams.get('state') as string;
    const replay = await http.request(`/auth/social/google/callback?code=c&state=${state}`, {
      headers: { cookie: replayed.header() },
    });
    replayed.absorb(replay);
    const fresh = new Browser(http);
    const replayAttempt = await http.request(`/auth/social/google/callback?code=c&state=${state}`, {
      headers: { cookie: fresh.header() },
    });
    fresh.absorb(replayAttempt);
    expect(failureCode(replayAttempt)).toBe('invalid_state');
    expect(fresh.session).toBeUndefined();

    expect(requests.filter(({ path }) => path === '/token')).toHaveLength(1);
    await app.shutdown();
  });

  test('a failed state check also clears the state, so it cannot be retried', async () => {
    const { app, http } = await buildApp();
    const browser = new Browser(http);
    const url = await browser.start();
    const forged = await http.request('/auth/social/google/callback?code=c&state=forged', {
      headers: { cookie: browser.header() },
    });
    browser.absorb(forged);

    const retried = await http.request(
      `/auth/social/google/callback?code=c&state=${url.searchParams.get('state')}`,
      { headers: { cookie: browser.header() } },
    );
    browser.absorb(retried);

    expect(failureCode(retried)).toBe('invalid_state');
    await app.shutdown();
  });

  test('state from one provider is refused on another', async () => {
    const { app, http } = await buildApp({
      providers: {
        google: { clientId: 'google-id', clientSecret: providerSecret('google') },
        github: { clientId: 'github-id', clientSecret: providerSecret('github') },
      },
      redirects: { google: `${APP}/g`, github: `${APP}/h` },
    });
    const browser = new Browser(http);
    const url = await browser.start('google');

    const response = await http.request(
      `/auth/social/github/callback?code=c&state=${url.searchParams.get('state')}`,
      { headers: { cookie: browser.header() } },
    );
    browser.absorb(response);

    expect(failureCode(response)).toBe('invalid_state');
    await app.shutdown();
  });

  test('a tampered state cookie is refused rather than crashing', async () => {
    const { app, http } = await buildApp();
    const browser = new Browser(http);
    const url = await browser.start();
    for (const name of browser.cookies.keys()) browser.cookies.set(name, 'not-json');

    const response = await http.request(
      `/auth/social/google/callback?code=c&state=${url.searchParams.get('state')}`,
      { headers: { cookie: browser.header() } },
    );
    browser.absorb(response);

    expect(failureCode(response)).toBe('invalid_state');
    await app.shutdown();
  });
});

describe('provider failures', () => {
  test('a denied consent redirects with a fixed code, not the provider text', async () => {
    const { app, http } = await buildApp();
    const browser = new Browser(http);
    const url = await browser.start();

    const response = await http.request(
      `/auth/social/google/callback?error=access_denied&error_description=${encodeURIComponent('<script>')}&state=${url.searchParams.get('state')}`,
      { headers: { cookie: browser.header() } },
    );
    browser.absorb(response);

    expect(failureCode(response)).toBe('provider_denied');
    expect(response.headers.get('location')).not.toContain('script');
    await app.shutdown();
  });

  test('a refused code exchange fails without a session, and without the secret', async () => {
    tokenResponse = () =>
      Response.json({ error: 'bad_verification_code', error_description: 'google-secret' }, { status: 200 });
    const { app, http } = await buildApp();
    const browser = new Browser(http);

    const response = await browser.login();

    expect(failureCode(response)).toBe('provider_error');
    expect(response.headers.get('location')).not.toContain('google-secret');
    expect(browser.session).toBeUndefined();
    await app.shutdown();
  });

  test('an unreachable provider fails the same way', async () => {
    const unreachable = googleDriver({
      clientId: 'x',
      clientSecret: 'y',
      endpoints: {
        authorize: 'https://idp.example/a',
        token: 'http://127.0.0.1:1/token',
        user: 'http://127.0.0.1:1/u',
      },
    });

    await expect(unreachable.exchangeCode({ code: 'c', redirectUri: 'https://x' })).rejects.toMatchObject({
      code: 'SOCIAL_PROVIDER_FAILED',
    });
  });

  test('a bug in a driver or the app is a 500, not disguised as a provider failure', async () => {
    const buggy = defineSocialDriver({
      name: 'buggy',
      usesPkce: false,
      redirectUrl: ({ state }) => `https://idp.example/a?state=${state}`,
      exchangeCode: async () => {
        throw new TypeError('a local bug');
      },
      fetchUser: async () => {
        throw new Error('unreached');
      },
    });
    const socialite = {
      ...socialConfig,
      providers: { buggy: { clientId: 'x', clientSecret: 'y' } },
      redirects: { buggy: `${APP}/cb` },
    };
    const config: Config = { auth: defaultAuthConfig, socialite };
    const app = new Application<Config>({
      config,
      providers: [
        {
          name: 'database',
          register({ container }) {
            container.value(TEST_CONNECTION, connection);
          },
        },
        createAuthProvider<Config>({ connection: TEST_CONNECTION }),
        createSocialiteProvider<Config>({ connection: TEST_CONNECTION, drivers: [buggy] }),
      ],
    });
    await app.boot();
    const http = createHttpKernel(app, { exposeInternalErrors: false, resolveActor: authActorResolver(app) });
    http.route('/s', socialiteRoutes({ session: defaultAuthConfig.session, config: socialite, secure: false }));
    const browser = new Browser(http);
    const redirect = await http.request('/s/buggy/redirect', { headers: { cookie: browser.header() } });
    browser.absorb(redirect);
    const url = new URL(redirect.headers.get('location') as string);

    const response = await http.request(`/s/buggy/callback?code=c&state=${url.searchParams.get('state')}`, {
      headers: { cookie: browser.header() },
    });
    browser.absorb(response);

    expect(response.status).toBe(500);
    await app.shutdown();
  });

  test('a provider outage fails the same way', async () => {
    tokenResponse = () => new Response('oops', { status: 500 });
    const { app, http } = await buildApp();

    expect(failureCode(await new Browser(http).login())).toBe('provider_error');
    await app.shutdown();
  });
});

describe('account takeover protection', () => {
  test('without linkByEmail, an existing email is a conflict, never a login', async () => {
    const { app, http } = await buildApp();
    const email = `${crypto.randomUUID()}@example.com`;
    const user = await localUser(app, email, true);
    profile = verifiedProfile('attacker-identity', email);
    const browser = new Browser(http);

    const response = await browser.login();

    expect(failureCode(response)).toBe('email_in_use');
    expect(browser.session).toBeUndefined();
    expect(await accountsFor(user.id)).toEqual([]);
    await app.shutdown();
  });

  test('linkByEmail links only when both sides verified the address', async () => {
    const { app, http } = await buildApp({ linkByEmail: true });
    const email = `${crypto.randomUUID()}@example.com`;
    const user = await localUser(app, email, true);
    profile = verifiedProfile(`linked-${crypto.randomUUID()}`, email);
    const browser = new Browser(http);

    expect((await browser.login()).headers.get('location')).toBe(SUCCESS);

    expect(await accountsFor(user.id)).toEqual([{ provider: 'google' }]);
    await app.shutdown();
  });

  test('linkByEmail refuses a provider email it did not verify', async () => {
    const { app, http } = await buildApp({ linkByEmail: true });
    const email = `${crypto.randomUUID()}@example.com`;
    const user = await localUser(app, email, true);
    profile = { ...verifiedProfile('unverified-claim', email), email_verified: false };
    const browser = new Browser(http);

    expect(failureCode(await browser.login())).toBe('email_in_use');
    expect(browser.session).toBeUndefined();
    expect(await accountsFor(user.id)).toEqual([]);
    await app.shutdown();
  });

  test('linkByEmail refuses a local account that never verified, so a pre-registered password cannot stay active', async () => {
    const { app, http } = await buildApp({ linkByEmail: true });
    const email = `${crypto.randomUUID()}@example.com`;
    const squatter = await localUser(app, email, false);
    profile = verifiedProfile(`victim-${crypto.randomUUID()}`, email);
    const browser = new Browser(http);

    expect(failureCode(await browser.login())).toBe('email_in_use');
    expect(browser.session).toBeUndefined();
    expect(await accountsFor(squatter.id)).toEqual([]);
    await app.shutdown();
  });

  test('an unverified provider email cannot register', async () => {
    const { app, http } = await buildApp();
    profile = {
      ...verifiedProfile(`u-${crypto.randomUUID()}`, `${crypto.randomUUID()}@example.com`),
      email_verified: false,
    };

    expect(failureCode(await new Browser(http).login())).toBe('email_unverified');
    await app.shutdown();
  });

  test('a provider that gives no email cannot register', async () => {
    const { app, http } = await buildApp();
    profile = { sub: `n-${crypto.randomUUID()}`, name: 'No Email' };

    expect(failureCode(await new Browser(http).login())).toBe('email_unverified');
    await app.shutdown();
  });

  test('registration can be turned off', async () => {
    const { app, http } = await buildApp({ registration: false });

    expect(failureCode(await new Browser(http).login())).toBe('registration_closed');
    await app.shutdown();
  });
});

describe('two-step login', () => {
  test('a user with two-step enabled gets a challenge, not a session', async () => {
    const { app, http } = await buildApp();
    await new Browser(http).login();
    const user = await app.container.resolve(USER_PROVIDER).findByEmail(profile.email as string);
    await app.container.resolve(USER_PROVIDER).setTotpSecret(user?.id as string, 'JBSWY3DPEHPK3PXP');
    const browser = new Browser(http);

    const response = await browser.login();
    const location = response.headers.get('location') as string;

    expect(browser.session).toBeUndefined();
    expect(location.startsWith(`${TWO_STEP}#challenge=`)).toBe(true);
    expect(location.split('challenge=')[1]?.length).toBeGreaterThanOrEqual(16);
    await app.shutdown();
  });

  test('without a twoStepRedirect the login fails rather than skipping the second factor', async () => {
    const { app, http } = await buildApp({ twoStepRedirect: undefined });
    await new Browser(http).login();
    const user = await app.container.resolve(USER_PROVIDER).findByEmail(profile.email as string);
    await app.container.resolve(USER_PROVIDER).setTotpSecret(user?.id as string, 'JBSWY3DPEHPK3PXP');
    const browser = new Browser(http);

    expect(failureCode(await browser.login())).toBe('two_step_required');
    expect(browser.session).toBeUndefined();
    await app.shutdown();
  });
});

describe('linking while logged in', () => {
  const loggedIn = async (app: Application<Config>, http: Http) => {
    const email = `${crypto.randomUUID()}@example.com`;
    const user = await localUser(app, email, true);
    const { sessionToken } = await app.container.resolve(AUTH_SERVICE).startSession(user.id);
    const browser = new Browser(http);
    browser.cookies.set(defaultAuthConfig.session.cookie, sessionToken);
    return { user, browser };
  };


  test('links the provider to the logged-in user, even with a different email', async () => {
    const { app, http } = await buildApp();
    const { user, browser } = await loggedIn(app, http);
    const state = (await browser.link()).searchParams.get('state') as string;

    const response = await http.request(`/auth/social/google/callback?code=c&state=${state}`, {
      headers: { cookie: browser.header() },
    });
    browser.absorb(response);

    expect(response.headers.get('location')).toBe(SUCCESS);
    expect(await accountsFor(user.id)).toEqual([{ provider: 'google' }]);
    await app.shutdown();
  });

  test('needs a login to start', async () => {
    const { app, http } = await buildApp();

    expect((await http.request('/auth/social/google/link', { method: 'POST' })).status).toBe(401);
    await app.shutdown();
  });

  test('is a POST, so a link on another site cannot start it', async () => {
    const { app, http } = await buildApp();
    const { browser } = await loggedIn(app, http);

    const linkProbe = await http.request('/auth/social/google/link', { headers: { cookie: browser.header() } });
    browser.absorb(linkProbe);
    expect(linkProbe.status).toBe(404);
    await app.shutdown();
  });

  test('refuses to finish if the session changed user mid-flow', async () => {
    const { app, http } = await buildApp();
    const { user, browser } = await loggedIn(app, http);
    const state = (await browser.link()).searchParams.get('state') as string;
    const other = await localUser(app, `${crypto.randomUUID()}@example.com`, true);
    const { sessionToken } = await app.container.resolve(AUTH_SERVICE).startSession(other.id);
    browser.cookies.set(defaultAuthConfig.session.cookie, sessionToken);

    const response = await http.request(`/auth/social/google/callback?code=c&state=${state}`, {
      headers: { cookie: browser.header() },
    });
    browser.absorb(response);

    expect(failureCode(response)).toBe('invalid_state');
    expect(await accountsFor(user.id)).toEqual([]);
    expect(await accountsFor(other.id)).toEqual([]);
    await app.shutdown();
  });

  test('refuses an identity already linked to someone else', async () => {
    const { app, http } = await buildApp();
    await new Browser(http).login();
    const { user, browser } = await loggedIn(app, http);
    const state = (await browser.link()).searchParams.get('state') as string;

    const response = await http.request(`/auth/social/google/callback?code=c&state=${state}`, {
      headers: { cookie: browser.header() },
    });
    browser.absorb(response);

    expect(failureCode(response)).toBe('already_linked');
    expect(await accountsFor(user.id)).toEqual([]);
    await app.shutdown();
  });

  test('unlinks with a DELETE, only for the caller', async () => {
    const { app, http } = await buildApp();
    const { user, browser } = await loggedIn(app, http);
    const state = (await browser.link()).searchParams.get('state') as string;
    const linked = await http.request(`/auth/social/google/callback?code=c&state=${state}`, {
      headers: { cookie: browser.header() },
    });
    browser.absorb(linked);

    expect((await http.request('/auth/social/google/link', { method: 'DELETE' })).status).toBe(401);
    expect(await accountsFor(user.id)).toHaveLength(1);
    const unlinked = await http.request('/auth/social/google/link', {
      method: 'DELETE',
      headers: { cookie: browser.header() },
    });
    browser.absorb(unlinked);
    expect(unlinked.status).toBe(204);
    expect(await accountsFor(user.id)).toEqual([]);
    await app.shutdown();
  });
});

describe('drivers', () => {
  test('github uses its verified primary email, not the public profile one', async () => {
    const { app, http } = await buildApp({
      providers: { github: { clientId: 'github-id', clientSecret: providerSecret('github') } },
      redirects: { github: `${APP}/auth/social/github/callback` },
    });
    const email = `${crypto.randomUUID()}@example.com`;
    profile = {
      id: 4242 + Math.floor(Math.random() * 1e9),
      login: 'octo',
      name: null,
      email: 'public@attacker.example',
      avatar_url: 'u',
    };
    githubEmails = [
      { email: 'other@example.com', primary: false, verified: true },
      { email, primary: true, verified: true },
    ];

    const response = await new Browser(http).login('github');

    expect(response.headers.get('location')).toBe(SUCCESS);
    const user = await app.container.resolve(USER_PROVIDER).findByEmail(email);
    expect(user?.name).toBe('octo');
    expect(requests.find(({ path }) => path === '/user')?.authorization).toBe(`Bearer ${providerAccessToken}`);
    await app.shutdown();
  });

  test('github treats an unverified primary email as unverified', async () => {
    const driver = githubDriver({
      clientId: 'id',
      clientSecret: 'secret',
      endpoints: { ...endpoints, emails: idpUrl('/user/emails') },
    });
    profile = { id: 7, login: 'octo', email: null };
    githubEmails = [{ email: 'a@example.com', primary: true, verified: false }];

    const user = await driver.fetchUser('token');

    expect(user).toMatchObject({ id: '7', email: 'a@example.com', emailVerified: false });
  });

  const appleOptions = () => ({
    clientId: 'com.example.app',
    teamId: 'TEAM123456',
    keyId: 'KEY1234567',
    privateKey: appleKey,
    endpoints: {
      authorize: 'https://idp.example/apple/authorize',
      token: idpUrl('/apple/token'),
      keys: idpUrl('/apple/keys'),
      issuer: 'https://appleid.apple.com',
    },
  });
  const signIdToken = (
    claims: Record<string, unknown>,
    audience = 'com.example.app',
    issuer = 'https://appleid.apple.com',
  ) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', kid: 'apple-key' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject('apple-user')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(appleKey);

  test('apple asks for a form post and signs its client secret per request', async () => {
    appleIdToken = () => signIdToken({ email: 'a@example.com', email_verified: 'true' });
    const driver = appleDriver(appleOptions());

    expect(driver.responseMode).toBe('form_post');
    expect(driver.redirectUrl({ state: 's', redirectUri: 'https://x/cb' })).toContain('response_mode=form_post');
    const tokens = await driver.exchangeCode({ code: 'c', redirectUri: 'https://x/cb' });
    const secret = requests.find(({ path }) => path === '/apple/token')?.form.client_secret as string;
    const [, payload = ''] = secret.split('.');

    expect(JSON.parse(Buffer.from(payload, 'base64url').toString())).toMatchObject({
      iss: 'TEAM123456',
      sub: 'com.example.app',
      aud: 'https://appleid.apple.com',
    });
    expect(tokens.idToken).toBeString();
  });

  test('apple reads the verified identity from a signed id token', async () => {
    appleIdToken = () => signIdToken({ email: 'a@example.com', email_verified: 'true' });
    const driver = appleDriver(appleOptions());
    const { accessToken, idToken } = await driver.exchangeCode({ code: 'c', redirectUri: 'https://x/cb' });

    expect(await driver.fetchUser(accessToken, idToken)).toMatchObject({
      id: 'apple-user',
      email: 'a@example.com',
      emailVerified: true,
    });
  });

  test('apple refuses a token for another app, from another issuer, or with a bad signature', async () => {
    const driver = appleDriver(appleOptions());
    const otherKey = (await generateKeyPair('ES256')).privateKey;
    const forged = await new SignJWT({ email: 'a@example.com' })
      .setProtectedHeader({ alg: 'ES256', kid: 'apple-key' })
      .setIssuer('https://appleid.apple.com')
      .setAudience('com.example.app')
      .setSubject('apple-user')
      .setExpirationTime('5m')
      .sign(otherKey);

    await expect(driver.fetchUser('a', await signIdToken({}, 'com.other.app'))).rejects.toThrow();
    await expect(driver.fetchUser('a', await signIdToken({}, 'com.example.app', 'https://evil'))).rejects.toThrow();
    await expect(driver.fetchUser('a', forged)).rejects.toThrow();
    await expect(driver.fetchUser('a')).rejects.toThrow();
  });

  test('a form-post callback gets a cross-site state cookie, which needs Secure', async () => {
    const manager = defineSocialDriver({
      name: 'postback',
      usesPkce: false,
      responseMode: 'form_post',
      redirectUrl: ({ state }) => `https://idp.example/a?state=${state}`,
      exchangeCode: async () => ({ accessToken: 't' }),
      fetchUser: async (): Promise<SocialUser> => ({
        id: 'p1',
        name: 'Post',
        email: `${crypto.randomUUID()}@example.com`,
        emailVerified: true,
        avatarUrl: null,
        raw: {},
      }),
    });
    const socialite = {
      ...socialConfig,
      providers: { postback: { clientId: 'x', clientSecret: 'y' } },
      redirects: { postback: `${APP}/cb` },
    };
    const config: Config = { auth: defaultAuthConfig, socialite };
    const app = new Application<Config>({
      config,
      providers: [
        {
          name: 'database',
          register({ container }) {
            container.value(TEST_CONNECTION, connection);
          },
        },
        createAuthProvider<Config>({ connection: TEST_CONNECTION }),
        createSocialiteProvider<Config>({ connection: TEST_CONNECTION, drivers: [manager] }),
      ],
    });
    await app.boot();
    const http = createHttpKernel(app, { exposeInternalErrors: false, resolveActor: authActorResolver(app) });
    http.route('/s', socialiteRoutes({ session: defaultAuthConfig.session, config: socialite, secure: true }));
    const browser = new Browser(http);

    const redirect = await http.request('/s/postback/redirect');
    const header = redirect.headers.getSetCookie()[0] ?? '';
    expect(header).toContain('SameSite=None');
    expect(header).toContain('Secure');

    const start = await http.request('/s/postback/redirect', { headers: { cookie: browser.header() } });
    browser.absorb(start);
    const state = new URL(start.headers.get('location') as string).searchParams.get('state') as string;
    const body = new URLSearchParams({ code: 'c', state });
    const response = await http.request('/s/postback/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: browser.header() },
      body,
    });
    browser.absorb(response);

    expect(response.status).toBe(303);
    expect(response.headers.get('location')).toBe(SUCCESS);
    await app.shutdown();
  });

  test('a POST callback is refused for a driver that does not use form post', async () => {
    const { app, http } = await buildApp();

    expect((await http.request('/auth/social/google/callback', { method: 'POST' })).status).toBe(404);
    await app.shutdown();
  });
});

describe('configuration', () => {
  test('the manager lists configured providers only', async () => {
    const { app } = await buildApp();

    expect(app.container.resolve(SOCIALITE_MANAGER).providers()).toEqual(['google']);
    expect(() => app.container.resolve(SOCIALITE_MANAGER).driver('github')).toThrow(FrameworkError);
    await app.shutdown();
  });

  test('a configured provider needs a redirect, or boot fails', async () => {
    await expect(buildApp({ redirects: {} })).rejects.toBeInstanceOf(BootError);
  });

  test('a redirect target must stay on this site', () => {
    const base = { providers: {}, redirects: {}, successRedirect: '/ok', failureRedirect: '/no' };

    expect(socialiteConfigSchema.safeParse(base).success).toBe(true);
    expect(socialiteConfigSchema.safeParse({ ...base, successRedirect: 'https://evil.example' }).success).toBe(false);
    expect(socialiteConfigSchema.safeParse({ ...base, failureRedirect: '//evil.example' }).success).toBe(false);
    expect(socialiteConfigSchema.safeParse({ ...base, successRedirect: '/\t/evil.example' }).success).toBe(false);
    expect(socialiteConfigSchema.safeParse({ ...base, successRedirect: '/\\evil.example' }).success).toBe(false);
    expect(socialiteConfigSchema.safeParse({ ...base, successRedirect: '/welcome?from=social' }).success).toBe(true);
  });

  test('defaults keep email linking off', () => {
    const parsed = socialiteConfigSchema.parse({
      providers: {},
      redirects: {},
      successRedirect: '/',
      failureRedirect: '/',
    });

    expect(parsed.linkByEmail).toBe(false);
    expect(parsed.registration).toBe(true);
  });

  test('stores keep one identity per provider', async () => {
    const { app } = await buildApp();
    const store = app.container.resolve(SOCIAL_ACCOUNT_STORE);
    const user = await localUser(app, `${crypto.randomUUID()}@example.com`, true);
    const id = crypto.randomUUID();

    await store.link('google', id, user.id);

    expect(await store.find('google', id)).toEqual({ userId: user.id });
    expect(await store.unlink(user.id, 'google')).toBe(true);
    expect(await store.unlink(user.id, 'google')).toBe(false);
    await app.shutdown();
  });
});
