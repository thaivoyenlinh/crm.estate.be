import { z } from "@hono/zod-openapi"
import type { Hook } from "@hono/zod-openapi"
import type { Context } from "hono"
import type { ContentfulStatusCode } from "hono/utils/http-status"

const PROBLEM_CONTENT_TYPE = "application/problem+json"

const TITLES: Partial<Record<ContentfulStatusCode, string>> = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  415: "Unsupported Media Type",
  429: "Too Many Requests",
  500: "Internal Server Error",
}

const FieldErrorSchema = z.object({ field: z.string(), message: z.string() })

export const ProblemSchema = z
  .object({
    code: z.string(),
    status: z.number().int(),
    title: z.string(),
    type: z.string(),
    errors: z.array(FieldErrorSchema).optional(),
  })
  .openapi("Problem")

type ProblemExtra = Pick<z.infer<typeof ProblemSchema>, "errors">

export const problem = <Status extends ContentfulStatusCode>(
  c: Context,
  status: Status,
  code: string,
  extra: ProblemExtra = {},
  headers: Record<string, string> = {},
) =>
  c.json(
    { code, status, title: TITLES[status] ?? "Error", type: "about:blank", ...extra },
    status,
    { "Content-Type": PROBLEM_CONTENT_TYPE, ...headers },
  )

export const problemResponse = (description: string) => ({
  content: { [PROBLEM_CONTENT_TYPE]: { schema: ProblemSchema } },
  description,
})

export const validationHook: Hook<unknown, any, any, unknown> = (result, c) => {
  if (result.success) {
    return
  }

  const errors = result.error.issues.map((issue) => ({
    field: issue.path.join("."),
    message: issue.message,
  }))
  return problem(c, 400, "validation_error", { errors })
}
