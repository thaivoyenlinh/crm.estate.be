import { createRoute, OpenAPIHono, z } from "@hono/zod-openapi"

import type { AppEnv } from "../../env"
import { problem, problemResponse, validationHook } from "../../lib/problem"
import { ACCESS_TOKEN_TTL_SECONDS } from "../../lib/tokens"
import { requireAuth } from "../../middleware/auth"
import { findActiveUser, login } from "./service"

const LoginRequestSchema = z
  .object({ email: z.email(), password: z.string().min(1) })
  .openapi("LoginRequest")

const TokenResponseSchema = z
  .object({ accessToken: z.string(), expiresIn: z.number().int() })
  .openapi("TokenResponse")

const UserSchema = z.object({ email: z.string(), id: z.string(), name: z.string() }).openapi("User")

const loginRoute = createRoute({
  method: "post",
  path: "/auth/login",
  request: {
    body: { content: { "application/json": { schema: LoginRequestSchema } }, required: true },
  },
  responses: {
    200: {
      content: { "application/json": { schema: TokenResponseSchema } },
      description: "Đăng nhập thành công",
    },
    400: problemResponse("validation_error"),
    401: problemResponse("invalid_credentials"),
    429: {
      ...problemResponse("too_many_attempts"),
      headers: z.object({ "Retry-After": z.string() }),
    },
  },
})

const meRoute = createRoute({
  method: "get",
  middleware: [requireAuth] as const,
  path: "/me",
  responses: {
    200: { content: { "application/json": { schema: UserSchema } }, description: "User hiện tại" },
    401: problemResponse("token_invalid"),
  },
  security: [{ Bearer: [] }],
})

export const authRoutes = new OpenAPIHono<AppEnv>({ defaultHook: validationHook })

authRoutes.openapi(loginRoute, async (c) => {
  const { email, password } = c.req.valid("json")
  const result = await login(c.env, email, password)

  switch (result.kind) {
    case "success":
      return c.json({ accessToken: result.accessToken, expiresIn: ACCESS_TOKEN_TTL_SECONDS }, 200)
    case "locked":
      return problem(c, 429, "too_many_attempts", {}, { "Retry-After": String(result.retryAfterSeconds) })
    case "invalid_credentials":
      return problem(c, 401, "invalid_credentials")
  }
})

authRoutes.openapi(meRoute, async (c) => {
  const user = await findActiveUser(c.env, c.get("userId"))

  if (user) {
    return c.json({ email: user.email, id: user.id, name: user.name }, 200)
  }

  return problem(c, 401, "token_invalid")
})
