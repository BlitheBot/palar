/**
 * Builds the environment object mcpguard passes to a spawned target.
 *
 * mcpguard itself never spreads `process.env` into a target's environment —
 * only what's explicitly declared on the discovered server config
 * (mcp.server.json's own "env" field, e.g. a value the tool legitimately
 * needs) is passed through, so ambient host credentials in mcpguard's own
 * process (CI secrets, cloud tokens, etc.) are never handed to a target
 * just because they happened to be in scope.
 *
 * Caveat, disclosed rather than hidden: @modelcontextprotocol/sdk's
 * StdioClientTransport internally merges its own hardcoded
 * getDefaultEnvironment() allowlist (on Windows: APPDATA, HOMEDRIVE,
 * HOMEPATH, LOCALAPPDATA, PATH, PROCESSOR_ARCHITECTURE, SYSTEMDRIVE,
 * SYSTEMROOT, TEMP, USERNAME, USERPROFILE, PROGRAMFILES; on POSIX: HOME,
 * LOGNAME, PATH, SHELL, TERM, USER) on top of whatever env object is
 * passed to it — this happens inside the SDK, unconditionally, and is not
 * something mcpguard can opt out of without replacing the transport
 * entirely. That allowlist holds no secrets, so it is a reasonable
 * baseline, but "no process.env inheritance" is true of mcpguard's own
 * contribution, not of the resulting child process environment as a
 * whole. This is a real limitation of the current dependency, not a false
 * claim — full control over the child's environment is part of the
 * sandboxing work that is NOT built yet (see connector.ts).
 */
export function buildCleanEnv(declaredEnv?: Record<string, string>): Record<string, string> {
  return { ...declaredEnv };
}
