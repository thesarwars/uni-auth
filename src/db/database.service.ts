import { Injectable, type OnModuleDestroy } from '@nestjs/common';
import pg from 'pg';
import { env } from '../config/env';

export type Db = Pick<pg.PoolClient, 'query'>;

/**
 * The identity database (auth-plan.md section 8), as the application's login role. The rules
 * live in the schema's triggers; this class only runs statements and transactions.
 */
@Injectable()
export class Database implements OnModuleDestroy {
  private readonly pool = new pg.Pool({ connectionString: env.DATABASE_URL, max: 10 });

  /** Runs `work` in one transaction: committed if it returns, rolled back if it throws. */
  async tx<T>(work: (db: Db) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  /** One statement outside any transaction. */
  async rows<T extends pg.QueryResultRow>(sql: string, params: unknown[] = []): Promise<T[]> {
    return (await this.pool.query<T>(sql, params)).rows;
  }

  /** The pool as a Db: each statement on its own, autocommitted. */
  asDb(): Db {
    return this.pool;
  }

  async ready(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }
}

export async function one<T extends pg.QueryResultRow>(
  db: Db,
  sql: string,
  params: unknown[] = [],
): Promise<T | null> {
  return (await db.query<T>(sql, params)).rows[0] ?? null;
}
