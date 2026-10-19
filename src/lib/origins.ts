export const parseAllowedOrigins = (env: Env) => env.ALLOWED_ORIGINS.split(",").map((origin) => origin.trim())
