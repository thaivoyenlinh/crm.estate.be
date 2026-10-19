import { DUMMY_PASSWORD_HASH, verifyPassword } from "../../lib/password"
import {
  generateRefreshToken,
  hashRefreshToken,
  REFRESH_TOKEN_TTL_SECONDS,
  signAccessToken,
} from "../../lib/tokens"
import {
  clearLoginAttempts,
  findUserByEmail,
  findUserById,
  insertRefreshToken,
  lockLogin,
  registerAttempt,
  revokeRefreshTokenFamily,
  rotateRefreshToken,
} from "./repo"
import type { LockPolicy } from "./repo"

const LOCK_POLICY: LockPolicy = {
  lockDurationMs: 15 * 60 * 1000,
  maxFailedAttempts: 5,
  windowMs: 15 * 60 * 1000,
}

export type Session = {
  accessToken: string
  refreshToken: string
}

export type LoginResult =
  | (Session & { kind: "success" })
  | { kind: "invalid_credentials" }
  | { kind: "locked"; retryAfterSeconds: number }

export type RefreshResult = (Session & { kind: "success" }) | { kind: "refresh_invalid" }

const locked = (lockedUntil: number, now: number): LoginResult => ({
  kind: "locked",
  retryAfterSeconds: Math.ceil((lockedUntil - now) / 1000),
})

const refreshExpiresAt = (now: number) => now + REFRESH_TOKEN_TTL_SECONDS * 1000

const issueSession = async (env: Env, userId: string): Promise<Session> => {
  const refreshToken = generateRefreshToken()

  await insertRefreshToken(env.DB, {
    expiresAt: refreshExpiresAt(Date.now()),
    familyId: crypto.randomUUID(),
    tokenHash: await hashRefreshToken(refreshToken),
    userId,
  })

  return { accessToken: await signAccessToken(userId, env.JWT_SECRET), refreshToken }
}

export const login = async (env: Env, rawEmail: string, password: string): Promise<LoginResult> => {
  const email = rawEmail.toLowerCase()
  const now = Date.now()
  const { attemptNumber, lockedUntil } = await registerAttempt(env.DB, email, now, LOCK_POLICY)

  if (lockedUntil) {
    return locked(lockedUntil, now)
  }

  const user = await findUserByEmail(env.DB, email)
  const isPasswordValid = await verifyPassword(password, user?.password_hash ?? DUMMY_PASSWORD_HASH)
  const canLogin = user?.is_active === 1 && isPasswordValid

  if (canLogin) {
    await clearLoginAttempts(env.DB, email)
    return { ...(await issueSession(env, user.id)), kind: "success" }
  }

  const isLastAllowedAttempt = attemptNumber >= LOCK_POLICY.maxFailedAttempts

  if (isLastAllowedAttempt) {
    const newLockedUntil = now + LOCK_POLICY.lockDurationMs
    await lockLogin(env.DB, email, newLockedUntil)
    return locked(newLockedUntil, now)
  }

  return { kind: "invalid_credentials" }
}

export const refreshSession = async (env: Env, refreshToken: string | undefined): Promise<RefreshResult> => {
  if (refreshToken) {
    const now = Date.now()
    const currentHash = await hashRefreshToken(refreshToken)
    const nextToken = generateRefreshToken()
    const userId = await rotateRefreshToken(env.DB, {
      currentHash,
      expiresAt: refreshExpiresAt(now),
      nextHash: await hashRefreshToken(nextToken),
      now,
    })

    if (userId) {
      return { accessToken: await signAccessToken(userId, env.JWT_SECRET), kind: "success", refreshToken: nextToken }
    }

    await revokeRefreshTokenFamily(env.DB, currentHash)
  }

  return { kind: "refresh_invalid" }
}

export const logout = async (env: Env, refreshToken: string | undefined) => {
  if (refreshToken) {
    await revokeRefreshTokenFamily(env.DB, await hashRefreshToken(refreshToken))
  }
}

export const findActiveUser = async (env: Env, id: string) => {
  const user = await findUserById(env.DB, id)
  return user?.is_active === 1 ? user : null
}
