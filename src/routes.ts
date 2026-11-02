import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  AUTH_SERVICE,
  type AuthConfig,
  authPrincipal,
  PASSWORD_HASHER,
  requireAuth,
  USER_PROVIDER,
} from '@framework/auth';
import { FrameworkError } from '@framework/core';
import { type FrameworkEnv, notFound, resolve } from '@framework/http';
import { type Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { z } from 'zod/v4';
import { SOCIAL_ACCOUNT_STORE, SOCIALITE_MANAGER } from './constants';
import { SocialLogin, SocialLoginError } from './login';
import type { SocialFailure, SocialiteConfig, SocialProvider, SocialUser } from './types';

const STATE_COOKIE = 'fw_social_state';
/** Browsers only accept this name from this exact host over HTTPS, so a subdomain can't plant one. */
const SECURE_STATE_COOKIE = `__Host-${STATE_COOKIE}`;
const STATE_TTL_SECONDS = 600;
const RANDOM_BYTES = 32;

export interface SocialiteRoutesOptions {
  /** The auth session settings, so a social login sets the same cookie as a password one. */
  readonly session: Pick<AuthConfig['session'], 'cookie' | 'ttlSeconds' | 'secure'>;
  readonly config: Pick<
    SocialiteConfig,
    'redirects' | 'linkByEmail' | 'registration' | 'successRedirect' | 'failureRedirect' | 'twoStepRedirect'
  >;
  /** Marks the state cookie `Secure`. Defaults to the session's setting. */
  readonly secure?: boolean;
}

const pendingSchema = z.object({
  provider: z.string(),
  state: z.string(),
  verifier: z.string().optional(),
  linkUserId: z.string().optional(),
});

type Pending = z.output<typeof pendingSchema>;

const random = (): string => randomBytes(RANDOM_BYTES).toString('base64url');
const challengeOf = (verifier: string): string => createHash('sha256').update(verifier).digest('base64url');

function sameText(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function readPending(value: string | undefined): Pending | null {
  if (!value) return null;
  try {
    return pendingSchema.parse(JSON.parse(Buffer.from(value, 'base64url').toString()));
  } catch {
    return null;
  }
}

/**
 * Social login endpoints, mounted by the application:
 *
 * ```text
 * GET    /:provider/redirect   start a login
 * GET    /:provider/callback   the provider returns here (POST for form-post drivers)
 * POST   /:provider/link       link the provider to the signed-in user
 * DELETE /:provider/link       unlink it
 * ```
 *
 * `state` and the PKCE verifier stay in an httpOnly cookie, single-use and short-lived,
 * and every outcome redirects to a configured path with a fixed error code.
 */
export function socialiteRoutes(options: SocialiteRoutesOptions): Hono<FrameworkEnv> {
  const { session, config } = options;
  const secure = options.secure ?? session.secure;

  const driverFor = (c: Context<FrameworkEnv>): SocialProvider => {
    const manager = resolve(c, SOCIALITE_MANAGER);
    const name = c.req.param('provider') ?? '';
    if (!manager.providers().includes(name)) throw notFound('Unknown social provider');
    return manager.driver(name);
  };

  /** A form-post provider needs a cross-site cookie, which browsers require to be `Secure`. */
  const stateCookieFor = (driver: SocialProvider): string =>
    secure || driver.responseMode === 'form_post' ? SECURE_STATE_COOKIE : STATE_COOKIE;

  const start = (c: Context<FrameworkEnv>, driver: SocialProvider, linkUserId?: string): string => {
    const redirectUri = config.redirects[driver.name] as string;
    const verifier = driver.usesPkce ? random() : undefined;
    const pending: Pending = {
      provider: driver.name,
      state: random(),
      ...(verifier ? { verifier } : {}),
      ...(linkUserId ? { linkUserId } : {}),
    };
    const crossSite = driver.responseMode === 'form_post';
    setCookie(c, stateCookieFor(driver), Buffer.from(JSON.stringify(pending)).toString('base64url'), {
      httpOnly: true,
      // A provider's form post back is cross-site, and only `None` cookies travel with it.
      sameSite: crossSite ? 'None' : 'Lax',
      secure: crossSite || secure,
      path: '/',
      maxAge: STATE_TTL_SECONDS,
    });
    return driver.redirectUrl({
      state: pending.state,
      redirectUri,
      ...(verifier ? { codeChallenge: challengeOf(verifier) } : {}),
    });
  };

  const fail = (c: Context<FrameworkEnv>, status: 302 | 303, failure: SocialFailure): Response =>
    c.redirect(`${config.failureRedirect}?error=${failure}`, status);

  const login = new SocialLoginFactory(config);

  const callback = async (c: Context<FrameworkEnv>, input: Readonly<Record<string, string | undefined>>) => {
    const driver = driverFor(c);
    const status = driver.responseMode === 'form_post' ? 303 : 302;
    // Read once and cleared whatever happens, so a state can never be tried twice.
    const cookie = stateCookieFor(driver);
    const pending = readPending(getCookie(c, cookie));
    deleteCookie(c, cookie, { path: '/', secure: cookie === SECURE_STATE_COOKIE });
    if (!pending || pending.provider !== driver.name || !input.state || !sameText(pending.state, input.state)) {
      return fail(c, status, 'invalid_state');
    }
    if (pending.linkUserId && authPrincipal(c)?.id !== pending.linkUserId) return fail(c, status, 'invalid_state');
    if (input.error || !input.code) return fail(c, status, 'provider_denied');

    let identity: SocialUser;
    try {
      const tokens = await driver.exchangeCode({
        code: input.code,
        redirectUri: config.redirects[driver.name] as string,
        ...(pending.verifier ? { codeVerifier: pending.verifier } : {}),
      });
      identity = await driver.fetchUser(tokens.accessToken, tokens.idToken);
    } catch (error) {
      // Only what a driver reports as the provider's fault: a local bug stays a loud 500.
      if (error instanceof FrameworkError && error.code === 'SOCIAL_PROVIDER_FAILED') {
        return fail(c, status, 'provider_error');
      }
      throw error;
    }

    const service = login.for(c);
    try {
      if (pending.linkUserId) {
        await service.link(driver.name, identity, pending.linkUserId);
        return c.redirect(config.successRedirect, status);
      }
      const user = await service.resolveUser(driver.name, identity);
      const started = await resolve(c, AUTH_SERVICE).startLoginFor(user);
      if (started.kind === 'two-step') {
        if (!config.twoStepRedirect) return fail(c, status, 'two_step_required');
        // In the fragment, which browsers don't send to servers or in a Referer.
        return c.redirect(`${config.twoStepRedirect}#challenge=${encodeURIComponent(started.challenge)}`, status);
      }
      setCookie(c, session.cookie, started.sessionToken, {
        httpOnly: true,
        sameSite: 'Lax',
        path: '/',
        secure: session.secure,
        maxAge: session.ttlSeconds,
      });
      return c.redirect(config.successRedirect, status);
    } catch (error) {
      if (error instanceof SocialLoginError) return fail(c, status, error.failure);
      throw error;
    }
  };

  return new Hono<FrameworkEnv>()
    .get('/:provider/redirect', (c) => c.redirect(start(c, driverFor(c)), 302))
    .get('/:provider/callback', (c) => callback(c, c.req.query()))
    .post('/:provider/callback', async (c) => {
      if (driverFor(c).responseMode !== 'form_post') throw notFound('Unknown social provider');
      const form = await c.req.parseBody();
      return callback(
        c,
        Object.fromEntries(
          ['code', 'state', 'error'].map((key) => [key, typeof form[key] === 'string' ? form[key] : undefined]),
        ),
      );
    })
    .post('/:provider/link', requireAuth(), (c) => {
      const principal = authPrincipal(c);
      return c.redirect(start(c, driverFor(c), principal?.id), 303);
    })
    .delete('/:provider/link', requireAuth(), async (c) => {
      const driver = driverFor(c);
      await resolve(c, SOCIAL_ACCOUNT_STORE).unlink(authPrincipal(c)?.id as string, driver.name);
      return c.body(null, 204);
    });
}

class SocialLoginFactory {
  constructor(private readonly config: SocialiteRoutesOptions['config']) {}

  for(c: Context<FrameworkEnv>): SocialLogin {
    return new SocialLogin({
      users: resolve(c, USER_PROVIDER),
      hasher: resolve(c, PASSWORD_HASHER),
      accounts: resolve(c, SOCIAL_ACCOUNT_STORE),
      config: this.config,
    });
  }
}
