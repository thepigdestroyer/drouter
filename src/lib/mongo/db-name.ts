/**
 * Resolves the MongoDB database name so tests never write to the production
 * `"drouter"` database.
 * - Uses `process.env.MONGODB_DB` if set and non-empty.
 * - Uses `"drouter_test"` when `process.env.VITEST` is set.
 * - Defaults to `"drouter"`.
 */
export const PRODUCTION_DB_NAME = "drouter";
export const TEST_DB_NAME = "drouter_test";

export function resolveDbName(): string {
  const explicit = process.env.MONGODB_DB?.trim();
  if (explicit) {
    return explicit;
  }
  if (process.env.VITEST) {
    return TEST_DB_NAME;
  }
  return PRODUCTION_DB_NAME;
}
