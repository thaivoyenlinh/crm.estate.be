import { mkdirSync, writeFileSync } from "node:fs"
import { z } from "zod"

import { hashPassword } from "../src/lib/password.ts"

const SEED_FILE = ".wrangler/seed-user.sql"

const [rawEmail, name, password] = process.argv.slice(2)
const hasValidArguments = z.email().safeParse(rawEmail).success && Boolean(name && password)

if (hasValidArguments) {
  const quote = (value: string) => `'${value.replaceAll("'", "''")}'`
  const email = rawEmail.toLowerCase()
  const passwordHash = await hashPassword(password)
  const values = [crypto.randomUUID(), email, name, passwordHash].map(quote).join(", ")

  mkdirSync(".wrangler", { recursive: true })
  writeFileSync(SEED_FILE, `INSERT INTO users (id, email, name, password_hash) VALUES (${values});\n`)
  console.log(`Đã ghi ${SEED_FILE}. Chạy: pnpm db:seed:local`)
} else {
  console.error("Cách dùng: pnpm seed:user <email hợp lệ> <tên> <mật khẩu>")
  process.exitCode = 1
}
