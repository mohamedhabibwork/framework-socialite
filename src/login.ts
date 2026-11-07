import { randomBytes } from 'node:crypto';
import type { AuthUser, PasswordHasher, UserProvider } from '@framework/auth';
import { FrameworkError } from '@framework/core';
import type { SocialAccountStore, SocialFailure, SocialiteConfig, SocialUser } from './types';

const RANDOM_PASSWORD_BYTES = 32;
const UNIQUE_VIOLATION = '23505';

/** A failure the routes report through `failureRedirect`, by its fixed code. */
export class SocialLoginError extends FrameworkError {
  constructor(readonly failure: SocialFailure) {
    super('SOCIAL_LOGIN_FAILED', `Social login failed: ${failure}`);
  }
}

export interface SocialLoginDeps {
  readonly users: UserProvider;
  readonly hasher: PasswordHasher;
  readonly accounts: SocialAccountStore;
  readonly config: Pick<SocialiteConfig, 'linkByEmail' | 'registration'>;
}

const isUniqueViolation = (error: unknown): boolean => {
  for (let current = error; current instanceof Error; current = current.cause) {
    if ((current as { code?: unknown }).code === UNIQUE_VIOLATION) return true;
  }
  return false;
};

/**
 * Decides which user a provider identity is, and whether it may sign in. An email
 * match is a takeover risk in both directions: an attacker can claim an address
 * at a provider that doesn't verify it, or pre-register a local account for a
 * victim's address and keep its password after the victim links. So it links only
 * when the app opted in and both sides verified the address.
 */
export class SocialLogin {
  constructor(private readonly deps: SocialLoginDeps) {}

  async resolveUser(provider: string, identity: SocialUser): Promise<AuthUser> {
    const { users, accounts } = this.deps;
    const linked = await accounts.find(provider, identity.id);
    if (linked) {
      const user = await users.findById(linked.userId);
      if (user) return user;
    }
    const existing = identity.email ? await users.findByEmail(identity.email.trim().toLowerCase()) : null;
    if (existing) return this.#linkByEmail(provider, identity, existing);
    return this.#register(provider, identity);
  }

  /** Links a provider to a signed-in user, who has just proved they hold both accounts. */
  async link(provider: string, identity: SocialUser, userId: string): Promise<void> {
    const linked = await this.deps.accounts.find(provider, identity.id);
    if (linked) {
      if (linked.userId === userId) return;
      throw new SocialLoginError('already_linked');
    }
    await this.deps.accounts.link(provider, identity.id, userId).catch((error: unknown) => {
      throw isUniqueViolation(error) ? new SocialLoginError('already_linked') : error;
    });
  }

  async #linkByEmail(provider: string, identity: SocialUser, user: AuthUser): Promise<AuthUser> {
    const allowed = this.deps.config.linkByEmail && identity.emailVerified && user.emailVerifiedAt !== null;
    if (!allowed) throw new SocialLoginError('email_in_use');
    await this.deps.accounts.link(provider, identity.id, user.id).catch((error: unknown) => {
      throw isUniqueViolation(error) ? new SocialLoginError('already_linked') : error;
    });
    return user;
  }

  async #register(provider: string, identity: SocialUser): Promise<AuthUser> {
    if (!this.deps.config.registration) throw new SocialLoginError('registration_closed');
    if (!identity.email || !identity.emailVerified) throw new SocialLoginError('email_unverified');
    const { users, hasher, accounts } = this.deps;
    // Nobody knows this password; the account signs in through the provider or password recovery.
    const passwordHash = await hasher.hash(randomBytes(RANDOM_PASSWORD_BYTES).toString('base64url'));
    const user = await users
      .create({ name: identity.name, email: identity.email.trim().toLowerCase(), passwordHash })
      .catch((error: unknown) => {
        throw isUniqueViolation(error) ? new SocialLoginError('email_in_use') : error;
      });
    await users.markEmailVerified(user.id);
    await accounts.link(provider, identity.id, user.id).catch((error: unknown) => {
      throw isUniqueViolation(error) ? new SocialLoginError('already_linked') : error;
    });
    return (await users.findById(user.id)) ?? user;
  }
}
