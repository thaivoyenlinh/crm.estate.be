const HASH_ALGORITHM = "pbkdf2_sha256"
const HASH_BITS = 256
const PBKDF2_ITERATIONS = 10_000
const SALT_BYTES = 16

export const DUMMY_PASSWORD_HASH =
  "pbkdf2_sha256$10000$zscZxPqxsfJzE8KfB0gEVg==$UKj01y/LxkE4zFoiYd6AT2/IWcdUXBudqu1QNP1Se4A="

const encoder = new TextEncoder()

const toBase64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))

const fromBase64 = (value: string) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0))

const derive = async (password: string, salt: Uint8Array<ArrayBuffer>, iterations: number) => {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, [
    "deriveBits",
  ])
  const bits = await crypto.subtle.deriveBits(
    { hash: "SHA-256", iterations, name: "PBKDF2", salt },
    key,
    HASH_BITS,
  )
  return new Uint8Array(bits)
}

export const hashPassword = async (password: string) => {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES))
  const hash = await derive(password, salt, PBKDF2_ITERATIONS)
  return [HASH_ALGORITHM, PBKDF2_ITERATIONS, toBase64(salt), toBase64(hash)].join("$")
}

export const verifyPassword = async (password: string, storedHash: string) => {
  const [algorithm, iterations, salt, hash] = storedHash.split("$")
  const isKnownFormat = algorithm === HASH_ALGORITHM && Number.isInteger(Number(iterations))

  if (isKnownFormat) {
    const expected = fromBase64(hash)
    const actual = await derive(password, fromBase64(salt), Number(iterations))
    return actual.byteLength === expected.byteLength && crypto.subtle.timingSafeEqual(actual, expected)
  }

  return false
}
