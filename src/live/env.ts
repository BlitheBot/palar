/**
 * Builds the environment object mcpguard hands to a spawned target's
 * declared env vars. mcpguard itself never spreads `process.env` into
 * this — only what's explicitly declared on the discovered server config
 * (mcp.server.json's own "env" field, e.g. a value the tool legitimately
 * needs) is passed through, so ambient host credentials in mcpguard's own
 * process (CI secrets, cloud tokens, etc.) are never handed to a target
 * just because they happened to be in scope.
 *
 * For stdio targets this is now consumed by sandbox.ts, which turns the
 * result into `-e KEY=VAL` flags on `docker run` — the container only ever
 * sees exactly these declared vars, nothing ambient. The caveat below is
 * about a different, narrower case: if buildCleanEnv()'s result were ever
 * passed straight to @modelcontextprotocol/sdk's StdioClientTransport
 * (spawning a target directly, unsandboxed — not something connector.ts
 * does anymore, but relevant if this function is reused elsewhere), the
 * SDK internally merges its own hardcoded getDefaultEnvironment()
 * allowlist (on Windows: APPDATA, HOMEDRIVE, HOMEPATH, LOCALAPPDATA, PATH,
 * PROCESSOR_ARCHITECTURE, SYSTEMDRIVE, SYSTEMROOT, TEMP, USERNAME,
 * USERPROFILE, PROGRAMFILES; on POSIX: HOME, LOGNAME, PATH, SHELL, TERM,
 * USER) on top of whatever env object is passed to it, unconditionally.
 * That allowlist holds no secrets, so it's a reasonable baseline, but "no
 * process.env inheritance" would be true of mcpguard's own contribution
 * there, not of the resulting child process environment as a whole.
 */
export function buildCleanEnv(declaredEnv?: Record<string, string>): Record<string, string> {
  return { ...declaredEnv };
}
