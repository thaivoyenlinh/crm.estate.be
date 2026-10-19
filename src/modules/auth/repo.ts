export type UserRow = {
  email: string
  id: string
  is_active: number
  name: string
  password_hash: string
}

export type LoginAttemptRow = {
  failed_count: number
  locked_until: number | null
  window_started_at: number
}

export type LockPolicy = {
  lockDurationMs: number
  maxFailedAttempts: number
  windowMs: number
}

export type NewRefreshToken = {
  expiresAt: number
  familyId: string
  tokenHash: string
  userId: string
}

export type RefreshTokenRotation = {
  currentHash: string
  expiresAt: number
  nextHash: string
  now: number
}

const USER_COLUMNS = "id, email, name, password_hash, is_active"

export const findUserByEmail = (db: D1Database, email: string) =>
  db.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE email = ?1`).bind(email).first<UserRow>()

export const findUserById = (db: D1Database, id: string) =>
  db.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?1`).bind(id).first<UserRow>()

export const registerAttempt = async (db: D1Database, email: string, now: number, policy: LockPolicy) => {
  const row = await db
    .prepare(
      `INSERT INTO login_attempts (email, failed_count, window_started_at, locked_until)
       VALUES (?1, 1, ?2, NULL)
       ON CONFLICT (email) DO UPDATE SET
         failed_count = CASE
           WHEN locked_until > ?2 THEN failed_count
           WHEN window_started_at <= ?2 - ?3 THEN 1
           ELSE failed_count + 1
         END,
         window_started_at = CASE
           WHEN locked_until > ?2 THEN window_started_at
           WHEN window_started_at <= ?2 - ?3 THEN ?2
           ELSE window_started_at
         END,
         locked_until = CASE
           WHEN locked_until > ?2 THEN locked_until
           WHEN window_started_at > ?2 - ?3 AND failed_count + 1 > ?4 THEN ?2 + ?5
         END
       RETURNING failed_count, locked_until`,
    )
    .bind(email, now, policy.windowMs, policy.maxFailedAttempts, policy.lockDurationMs)
    .first<Pick<LoginAttemptRow, "failed_count" | "locked_until">>()
  return { attemptNumber: row?.failed_count ?? 1, lockedUntil: row?.locked_until ?? null }
}

export const lockLogin = (db: D1Database, email: string, lockedUntil: number) =>
  db.prepare("UPDATE login_attempts SET locked_until = ?2 WHERE email = ?1").bind(email, lockedUntil).run()

export const clearLoginAttempts = (db: D1Database, email: string) =>
  db.prepare("DELETE FROM login_attempts WHERE email = ?1").bind(email).run()

export const insertRefreshToken = (db: D1Database, token: NewRefreshToken) =>
  db
    .prepare("INSERT INTO refresh_tokens (token_hash, family_id, user_id, expires_at) VALUES (?1, ?2, ?3, ?4)")
    .bind(token.tokenHash, token.familyId, token.userId, token.expiresAt)
    .run()

export const rotateRefreshToken = async (db: D1Database, rotation: RefreshTokenRotation) => {
  const [inserted] = await db.batch<Pick<UserRow, "id">>([
    db
      .prepare(
        `INSERT INTO refresh_tokens (token_hash, family_id, user_id, expires_at)
         SELECT ?2, refresh_tokens.family_id, refresh_tokens.user_id, ?4
         FROM refresh_tokens JOIN users ON users.id = refresh_tokens.user_id
         WHERE refresh_tokens.token_hash = ?1
           AND refresh_tokens.used_at IS NULL
           AND refresh_tokens.expires_at > ?3
           AND users.is_active = 1
         RETURNING user_id AS id`,
      )
      .bind(rotation.currentHash, rotation.nextHash, rotation.now, rotation.expiresAt),
    db
      .prepare("UPDATE refresh_tokens SET used_at = ?2 WHERE token_hash = ?1 AND used_at IS NULL")
      .bind(rotation.currentHash, rotation.now),
  ])
  return inserted.results[0]?.id ?? null
}

export const revokeRefreshTokenFamily = (db: D1Database, tokenHash: string) =>
  db
    .prepare(
      `DELETE FROM refresh_tokens
       WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = ?1)`,
    )
    .bind(tokenHash)
    .run()
