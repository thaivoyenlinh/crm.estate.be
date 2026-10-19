import { createMiddleware } from "hono/factory"

import type { AppEnv } from "../env"
import { parseAllowedOrigins } from "../lib/origins"
import { problem } from "../lib/problem"

const REQUESTED_WITH = "fetch"

export const requireCsrfHeaders = createMiddleware<AppEnv>(async (c, next) => {
  const origin = c.req.header("Origin") ?? ""
  const hasCustomHeader = c.req.header("X-Requested-With") === REQUESTED_WITH
  const isTrustedRequest = hasCustomHeader && parseAllowedOrigins(c.env).includes(origin)

  if (isTrustedRequest) {
    return next()
  }

  return problem(c, 403, "csrf_rejected")
})
