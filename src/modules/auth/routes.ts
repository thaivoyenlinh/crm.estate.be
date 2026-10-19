import { createRoute, OpenAPIHono, z } from "@hono/zod-openapi"
import type { Context } from "hono"
import { deleteCookie, setCookie } from "hono/cookie"
import type { CookieOptions } from "hono/utils/cookie"

import type { AppEnv } from "../../env"
import { problem, problemResponse, validationHook } from "../../lib/problem"
import { ACCESS_TOKEN_TTL_SECONDS, REFRESH_TOKEN_TTL_SECONDS } from "../../lib/tokens"
import { requireAuth } from "../../middleware/auth"
import { requireCsrfHeaders } from "../../middleware/csrf"
import { findActiveUser, login, logout, refreshSession } from "./service"

const REFRESH_COOKIE = "refresh_token"

const REFRESH_COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  path: "/auth",
  sameSite: "Strict",
  secure: true,
}

const setRefreshCookie = (c: Context, refreshToken: string) =>
  setCookie(c, REFRESH_COOKIE, refreshToken, { ...REFRESH_COOKIE_OPTIONS, maxAge: REFRESH_TOKEN_TTL_SECONDS })

const clearRefreshCookie = (c: Context) => deleteCookie(c, REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS)

const LoginRequestSchema = z
  .object({ email: z.email(), password: z.string().min(1) })
  .openapi("LoginRequest")

const TokenResponseSchema = z
  .object({ accessToken: z.string(), expiresIn: z.number().int() })
  .openapi("TokenResponse")

const UserSchema = z.object({ email: z.string(), id: z.string(), name: z.string() }).openapi("User")

const CsrfHeadersSchema = z.object({ "x-requested-with": z.literal("fetch") })

const RefreshCookieSchema = z.object({ [REFRESH_COOKIE]: z.string().optional() })

const SetCookieHeaderSchema = z.object({ "Set-Cookie": z.string() })

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
      headers: SetCookieHeaderSchema,
    },
    400: problemResponse("validation_error"),
    401: problemResponse("invalid_credentials"),
    429: {
      ...problemResponse("too_many_attempts"),
      headers: z.object({ "Retry-After": z.string() }),
    },
  },
})

const refreshRoute = createRoute({
  method: "post",
  middleware: [requireCsrfHeaders] as const,
  path: "/auth/refresh",
  request: { cookies: RefreshCookieSchema, headers: CsrfHeadersSchema },
  responses: {
    200: {
      content: { "application/json": { schema: TokenResponseSchema } },
      description: "Cấp access token mới và xoay vòng refresh token",
      headers: SetCookieHeaderSchema,
    },
    401: problemResponse("refresh_invalid"),
    403: problemResponse("csrf_rejected"),
  },
})

const logoutRoute = createRoute({
  method: "post",
  middleware: [requireCsrfHeaders] as const,
  path: "/auth/logout",
  request: { cookies: RefreshCookieSchema, headers: CsrfHeadersSchema },
  responses: {
    204: { description: "Đã đăng xuất, cookie refresh bị xoá", headers: SetCookieHeaderSchema },
    403: problemResponse("csrf_rejected"),
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
      setRefreshCookie(c, result.refreshToken)
      return c.json({ accessToken: result.accessToken, expiresIn: ACCESS_TOKEN_TTL_SECONDS }, 200)
    case "locked":
      return problem(c, 429, "too_many_attempts", {}, { "Retry-After": String(result.retryAfterSeconds) })
    case "invalid_credentials":
      return problem(c, 401, "invalid_credentials")
  }
})

authRoutes.openapi(refreshRoute, async (c) => {
  const result = await refreshSession(c.env, c.req.valid("cookie")[REFRESH_COOKIE])

  switch (result.kind) {
    case "success":
      setRefreshCookie(c, result.refreshToken)
      return c.json({ accessToken: result.accessToken, expiresIn: ACCESS_TOKEN_TTL_SECONDS }, 200)
    case "refresh_invalid":
      clearRefreshCookie(c)
      return problem(c, 401, "refresh_invalid")
  }
})

authRoutes.openapi(logoutRoute, async (c) => {
  await logout(c.env, c.req.valid("cookie")[REFRESH_COOKIE])
  clearRefreshCookie(c)
  return c.body(null, 204)
})

authRoutes.openapi(meRoute, async (c) => {
  const user = await findActiveUser(c.env, c.get("userId"))

  if (user) {
    return c.json({ email: user.email, id: user.id, name: user.name }, 200)
  }

  return problem(c, 401, "token_invalid")
})
