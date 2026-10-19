import { sign } from "hono/jwt"

export const ACCESS_TOKEN_TTL_SECONDS = 900

export const signAccessToken = (userId: string, secret: string) => {
  const issuedAt = Math.floor(Date.now() / 1000)
  return sign({ exp: issuedAt + ACCESS_TOKEN_TTL_SECONDS, iat: issuedAt, sub: userId }, secret, "HS256")
}
