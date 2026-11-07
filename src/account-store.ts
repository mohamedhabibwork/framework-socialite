import type { DatabaseConnection } from '@framework/database';
import { and, eq } from 'drizzle-orm';
import { socialAccounts } from './schema';
import type { SocialAccountStore } from './types';

/** Links identities in the `social_accounts` table. */
export class PgSocialAccountStore implements SocialAccountStore {
  constructor(private readonly connection: DatabaseConnection) {}

  async find(provider: string, providerUserId: string): Promise<{ readonly userId: string } | null> {
    const rows = await this.connection.db
      .select({ userId: socialAccounts.userId })
      .from(socialAccounts)
      .where(and(eq(socialAccounts.provider, provider), eq(socialAccounts.providerUserId, providerUserId)))
      .limit(1);
    return rows[0] ?? null;
  }

  async link(provider: string, providerUserId: string, userId: string): Promise<void> {
    await this.connection.db.insert(socialAccounts).values({ provider, providerUserId, userId });
  }

  async unlink(userId: string, provider: string): Promise<boolean> {
    const removed = await this.connection.db
      .delete(socialAccounts)
      .where(and(eq(socialAccounts.userId, userId), eq(socialAccounts.provider, provider)))
      .returning({ id: socialAccounts.id });
    return removed.length > 0;
  }
}
