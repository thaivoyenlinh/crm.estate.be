import { DUMMY_PASSWORD_HASH, verifyPassword } from "../../lib/password"
import { signAccessToken } from "../../lib/tokens"
import { clearLoginAttempts, findUserByEmail, findUserById, lockLogin, registerAttempt } from "./repo"
import type { LockPolicy } from "./repo"

const LOCK_POLICY: LockPolicy = {
  lockDurationMs: 15 * 60 * 1000,
  maxFailedAttempts: 5,
  windowMs: 15 * 60 * 1000,
}

export type LoginResult =
  | { accessToken: string; kind: "success" }
  | { kind: "invalid_credentials" }
  | { kind: "locked"; retryAfterSeconds: number }

const locked = (lockedUntil: number, now: number): LoginResult => ({
  kind: "locked",
  retryAfterSeconds: Math.ceil((lockedUntil - now) / 1000),
})

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
    return { accessToken: await signAccessToken(user.id, env.JWT_SECRET), kind: "success" }
  }

  const isLastAllowedAttempt = attemptNumber >= LOCK_POLICY.maxFailedAttempts

  if (isLastAllowedAttempt) {
    const newLockedUntil = now + LOCK_POLICY.lockDurationMs
    await lockLogin(env.DB, email, newLockedUntil)
    return locked(newLockedUntil, now)
  }

  return { kind: "invalid_credentials" }
}

export const findActiveUser = async (env: Env, id: string) => {
  const user = await findUserById(env.DB, id)
  return user?.is_active === 1 ? user : null
}
