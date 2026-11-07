import { ConfigError, defineProvider, type ServiceProvider, type Token } from '@framework/core';
import { DATABASE, type DatabaseConnection } from '@framework/database';
import { z } from 'zod/v4';
import { PgSocialAccountStore } from './account-store';
import { SOCIAL_ACCOUNT_STORE, SOCIALITE_MANAGER } from './constants';
import { appleDriver, githubDriver, googleDriver } from './drivers';
import { DriverRegistry } from './manager';
import type { SocialiteConfig, SocialProvider, SocialProviderConfig } from './types';

/** A path on this site. A full URL or `//host` would make the login an open redirect. */
const localPath = z.string().regex(/^\/(?![/\\])[^\s\\]*$/, 'Must be a path on this site, such as /welcome');

const providerSchema = z.object({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).optional(),
  scopes: z.array(z.string()).optional(),
  teamId: z.string().min(1).optional(),
  keyId: z.string().min(1).optional(),
  privateKey: z.string().min(1).optional(),
});

/** Validated shape of the application's `socialite` configuration section. */
export const socialiteConfigSchema = z.object({
  providers: z.record(z.string(), providerSchema),
  redirects: z.record(z.string(), z.url()),
  linkByEmail: z.boolean().default(false),
  registration: z.boolean().default(true),
  successRedirect: localPath,
  failureRedirect: localPath,
  twoStepRedirect: localPath.optional(),
});

const requireFields = (name: string, config: SocialProviderConfig, fields: readonly (keyof SocialProviderConfig)[]) => {
  const missing = fields.filter((field) => !config[field]);
  if (missing.length > 0) {
    throw new ConfigError(missing.map((field) => `socialite.providers.${name}.${field}: required`));
  }
};

function builtInDriver(name: string, config: SocialProviderConfig): SocialProvider | undefined {
  const scopes = config.scopes ? { scopes: config.scopes } : {};
  if (name === 'google' || name === 'github') {
    requireFields(name, config, ['clientSecret']);
    const client = { clientId: config.clientId, clientSecret: config.clientSecret as string, ...scopes };
    return name === 'google' ? googleDriver(client) : githubDriver(client);
  }
  if (name === 'apple') {
    requireFields(name, config, ['teamId', 'keyId', 'privateKey']);
    return appleDriver({
      clientId: config.clientId,
      teamId: config.teamId as string,
      keyId: config.keyId as string,
      privateKey: config.privateKey as string,
      ...scopes,
    });
  }
  return undefined;
}

export interface SocialiteProviderOptions {
  /** Connection token to build the account store on; defaults to `DATABASE`. */
  readonly connection?: Token<DatabaseConnection>;
  /** Custom or preconfigured drivers (see `defineSocialDriver`); these win over built-in ones of the same name. */
  readonly drivers?: readonly SocialProvider[];
}

/**
 * Registers the configured drivers and the account store. A provider in config
 * with no driver or no redirect fails boot, so a typo can't surface at login.
 */
export function createSocialiteProvider<TConfig extends { readonly socialite: SocialiteConfig }>(
  options: SocialiteProviderOptions = {},
): ServiceProvider<TConfig> {
  return defineProvider<TConfig>({
    name: 'socialite',
    dependsOn: ['auth'],
    register({ container, config }) {
      const custom = new Map((options.drivers ?? []).map((driver) => [driver.name, driver]));
      const drivers = Object.entries(config.socialite.providers).map(([name, provider]) => {
        if (!config.socialite.redirects[name]) {
          throw new ConfigError([`socialite.redirects.${name}: required for a configured provider`]);
        }
        const driver = custom.get(name) ?? builtInDriver(name, provider);
        if (!driver) throw new ConfigError([`socialite.providers.${name}: no driver has this name`]);
        return driver;
      });
      container.value(SOCIALITE_MANAGER, new DriverRegistry(drivers));
      const connection = options.connection ?? DATABASE;
      container.singleton(
        SOCIAL_ACCOUNT_STORE,
        (r) => new PgSocialAccountStore(r.resolve<DatabaseConnection>(connection)),
      );
    },
  });
}
