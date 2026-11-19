import { Injectable } from '@nestjs/common';
import { Database, type Db } from '../db/database.service';

export interface Photo {
  id: string;
  identityId: string;
  key: string;
}

/**
 * Profile photo records (db/migrations/0015_identity_photo.sql). One current per identity; the
 * rest are kept, with whether their object has been deleted yet.
 */
@Injectable()
export class PhotoRepository {
  constructor(private readonly db: Database) {}

  /** The identity's current photo's key, or null. */
  async currentKey(identityId: string, db: Db = this.db.asDb()): Promise<string | null> {
    const res = await db.query<{ object_key: string }>(
      `SELECT object_key FROM identity_photo WHERE identity_id = $1 AND replaced_at IS NULL`,
      [identityId],
    );
    return res.rows[0]?.object_key ?? null;
  }

  /** Whether the key is someone's current photo: only those are served. */
  async isCurrent(key: string): Promise<boolean> {
    const rows = await this.db.rows<{ one: number }>(
      `SELECT 1 AS one FROM identity_photo p JOIN identity i ON i.id = p.identity_id
        WHERE p.object_key = $1 AND p.replaced_at IS NULL AND i.erased_at IS NULL`,
      [key],
    );
    return rows.length > 0;
  }

  /** Replaces the current photo, if any, with this one. */
  async replace(db: Db, identityId: string, key: string, bytes: number): Promise<void> {
    await this.retire(db, identityId);
    await db.query(
      `INSERT INTO identity_photo (identity_id, object_key, bytes) VALUES ($1, $2, $3)`,
      [identityId, key, bytes],
    );
  }

  /** Takes the current photo down; returns whether there was one. */
  async retire(db: Db, identityId: string): Promise<boolean> {
    const res = await db.query(
      `UPDATE identity_photo SET replaced_at = now()
        WHERE identity_id = $1 AND replaced_at IS NULL`,
      [identityId],
    );
    return (res.rowCount ?? 0) > 0;
  }

  /** Replaced photos whose object is still in the bucket. */
  async toDelete(limit = 100): Promise<Photo[]> {
    return (
      await this.db.rows<{ id: string; identity_id: string; object_key: string }>(
        `SELECT id, identity_id, object_key FROM identity_photo
          WHERE replaced_at IS NOT NULL AND object_deleted_at IS NULL
          ORDER BY replaced_at LIMIT $1`,
        [limit],
      )
    ).map((r) => ({ id: r.id, identityId: r.identity_id, key: r.object_key }));
  }

  async markDeleted(id: string): Promise<void> {
    await this.db.rows(
      `UPDATE identity_photo SET object_deleted_at = now()
        WHERE id = $1 AND object_deleted_at IS NULL`,
      [id],
    );
  }
}
