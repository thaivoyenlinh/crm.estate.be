import { swaggerUI } from "@hono/swagger-ui"
import { OpenAPIHono } from "@hono/zod-openapi"
import { cors } from "hono/cors"
import { HTTPException } from "hono/http-exception"
import type { ContentfulStatusCode } from "hono/utils/http-status"

import type { AppEnv } from "./env"
import { parseAllowedOrigins } from "./lib/origins"
import { problem, validationHook } from "./lib/problem"
import { authRoutes } from "./modules/auth/routes"

const SWAGGER_UI_VERSION = "5.33.1"

const ERROR_CODES: Partial<Record<number, string>> = {
  400: "validation_error",
  415: "unsupported_media_type",
}

const app = new OpenAPIHono<AppEnv>({ defaultHook: validationHook })

app.use("*", (c, next) => {
  const allowedOrigins = parseAllowedOrigins(c.env)
  const handler = cors({
    allowHeaders: ["Authorization", "Content-Type", "X-Requested-With"],
    allowMethods: ["GET", "OPTIONS", "POST"],
    credentials: true,
    exposeHeaders: ["Retry-After"],
    maxAge: 600,
    origin: (origin) => (allowedOrigins.includes(origin) ? origin : null),
  })
  return handler(c, next)
})

app.route("/", authRoutes)

app.openAPIRegistry.registerComponent("securitySchemes", "Bearer", {
  bearerFormat: "JWT",
  scheme: "bearer",
  type: "http",
})

app.doc31("/doc", {
  info: { title: "crm.estate API", version: "1.0.0" },
  openapi: "3.1.0",
})

app.get("/ui", swaggerUI({ url: "/doc", version: SWAGGER_UI_VERSION }))

app.notFound((c) => problem(c, 404, "not_found"))

app.onError((error, c) => {
  if (error instanceof HTTPException) {
    const status = error.status as ContentfulStatusCode
    const extra = status === 400 ? { errors: [] } : {}
    return problem(c, status, ERROR_CODES[status] ?? "http_error", extra)
  }

  console.error(error)
  return problem(c, 500, "internal_error")
})

export default app
