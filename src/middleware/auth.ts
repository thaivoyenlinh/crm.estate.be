import { createMiddleware } from "hono/factory"
import { verify } from "hono/jwt"

import type { AppEnv } from "../env"
import { problem } from "../lib/problem"

const BEARER_PREFIX = "bearer "

export const requireAuth = createMiddleware<AppEnv>(async (c, next) => {
  const header = c.req.header("Authorization") ?? ""
  const isBearer = header.slice(0, BEARER_PREFIX.length).toLowerCase() === BEARER_PREFIX
  const token = isBearer ? header.slice(BEARER_PREFIX.length) : undefined

  try {
    const payload = await verify(token ?? "", c.env.JWT_SECRET, "HS256")
    const hasSubject = typeof payload.sub === "string"

    if (hasSubject) {
      c.set("userId", payload.sub as string)
      return next()
    }
  } catch {}

  return problem(c, 401, "token_invalid")
})
