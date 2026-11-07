import { FrameworkError } from '@framework/core';
import type { SocialiteManager, SocialProvider } from './types';

/** The configured drivers, by name. */
export class DriverRegistry implements SocialiteManager {
  readonly #drivers: ReadonlyMap<string, SocialProvider>;

  constructor(drivers: readonly SocialProvider[]) {
    this.#drivers = new Map(drivers.map((driver) => [driver.name, driver]));
  }

  driver(name: string): SocialProvider {
    const driver = this.#drivers.get(name);
    if (!driver) throw new FrameworkError('SOCIAL_PROVIDER_UNKNOWN', `No social provider named "${name}"`);
    return driver;
  }

  has(name: string): boolean {
    return this.#drivers.has(name);
  }

  providers(): readonly string[] {
    return [...this.#drivers.keys()];
  }
}
