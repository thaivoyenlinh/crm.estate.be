import { sign } from "hono/jwt"

export const ACCESS_TOKEN_TTL_SECONDS = 900
export const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60

const REFRESH_TOKEN_BYTES = 32

const encoder = new TextEncoder()

const toBase64Url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "")

export const signAccessToken = (userId: string, secret: string) => {
  const issuedAt = Math.floor(Date.now() / 1000)
  return sign({ exp: issuedAt + ACCESS_TOKEN_TTL_SECONDS, iat: issuedAt, sub: userId }, secret, "HS256")
}

export const generateRefreshToken = () =>
  toBase64Url(crypto.getRandomValues(new Uint8Array(REFRESH_TOKEN_BYTES)))

export const hashRefreshToken = async (token: string) =>
  toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(token))))
