import { users } from '@framework/auth';
import { index, pgTable, text, timestamp, unique, uuid } from 'drizzle-orm/pg-core';

/**
 * Provider identities linked to a user. Export it from your schema so Drizzle Kit
 * generates its migration. Provider tokens aren't kept: the framework only uses
 * them to read the identity once.
 */
export const socialAccounts = pgTable(
  'social_accounts',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    provider: text('provider').notNull(),
    providerUserId: text('provider_user_id').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true, mode: 'string' }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true, mode: 'string' })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date().toISOString()),
  },
  (table) => [
    unique('social_accounts_identity_unique').on(table.provider, table.providerUserId),
    unique('social_accounts_user_provider_unique').on(table.userId, table.provider),
    index('social_accounts_user_id_idx').on(table.userId),
  ],
);
