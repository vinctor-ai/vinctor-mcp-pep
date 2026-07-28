export function childEnv(
  env: Record<string, string | undefined>,
): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(env)) {
    if (!key.toUpperCase().startsWith("VINCTOR_")) out[key] = value;
  }
  return out;
}
