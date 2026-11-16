// Anisette server presets, default and the one-time store migration.
//
// Since about 2026-10-12 Apple rejects sign-ins whose anisette comes from an
// Android-ADI-backed server while the client claims to be a Mac (-80045 at
// init, -80046 at the token step since 10-22). Every server in the old preset
// list is Android-backed, so the presets are now the Mac-backed servers that
// upstream iloader ships (nab138/iloader 9025975 + 9797eca).

export const ANISETTE_SERVERS: [string, string][] = [
  ["mac-ani.jkcoxson.com", "Jkcoxson"],
  ["ani.iloader.app", "iloader"],
  ["new.ani.sidestore.io", "SideStore (.io)"],
  ["ani3.stikstore.app", "StikStore"],
];

export const DEFAULT_ANISETTE_SERVER = "mac-ani.jkcoxson.com";

// Store key for the selected server. Renamed from "anisetteServer" so that
// existing installs move to the new default instead of keeping an Android
// server (same approach as nab138/iloader cc5b168).
export const ANISETTE_SERVER_KEY = "anisetteServerMac1";
export const LEGACY_ANISETTE_SERVER_KEY = "anisetteServer";

// Every server that was a preset before 2.3.3, plus other public servers known
// to be Android-backed as of 2026-11-15. A legacy value on this list is
// dropped instead of migrated. ani.stikstore.app was an old preset, so a user
// who picked it from the dropdown also moves to the new default.
export const KNOWN_BAD_ANISETTE_SERVERS = [
  "ani.sidestore.io",
  "ani.stikstore.app",
  "ani.sidestore.app",
  "ani.sidestore.zip",
  "ani.846969.xyz",
  "ani.neoarz.xyz",
  "ani.xu30.top",
  "anisette.wedotstud.io",
  "ani.npeg.us",
];

/** Lowercased host (plus any path) with the scheme and trailing slashes removed. */
export const normalizeAnisetteHost = (server: string): string =>
  server
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
    .replace(/\/+$/, "");

export const isKnownBadAnisetteServer = (server: string): boolean =>
  KNOWN_BAD_ANISETTE_SERVERS.includes(normalizeAnisetteHost(server));

/**
 * Decide what the legacy "anisetteServer" value should become under the new
 * key. Returns the value to carry over (a user's own Custom server), or null
 * to fall back to DEFAULT_ANISETTE_SERVER.
 */
export const migrateLegacyAnisetteServer = (legacy: unknown): string | null => {
  if (typeof legacy !== "string") return null;
  const trimmed = legacy.trim();
  if (trimmed === "") return null;
  if (isKnownBadAnisetteServer(trimmed)) return null;
  return trimmed;
};

export type MigratableStore = {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  save(): Promise<void>;
};

/**
 * Run once at start-up, before the store values are read into React state.
 * Writes the new key only when it is unset and the legacy value is a Custom
 * server that is not known to be bad. Returns the value written, if any.
 */
export const migrateAnisetteServerKey = async (
  store: MigratableStore,
): Promise<string | null> => {
  const current = await store.get<string>(ANISETTE_SERVER_KEY);
  if (current !== undefined && current !== null) return null;
  const legacy = await store.get<string>(LEGACY_ANISETTE_SERVER_KEY);
  const migrated = migrateLegacyAnisetteServer(legacy);
  if (migrated === null) return null;
  await store.set(ANISETTE_SERVER_KEY, migrated);
  await store.save();
  return migrated;
};

export type InitialStore = MigratableStore & { keys(): Promise<string[]> };

/**
 * What StoreProvider runs at start-up: the anisette migration first, then read
 * every value. Kept here (no Tauri imports) so the ordering is unit-tested.
 * A failed migration is logged and does not block start-up.
 */
export const readInitialStoreValues = async (
  store: InitialStore,
): Promise<{ [key: string]: unknown }> => {
  try {
    await migrateAnisetteServerKey(store);
  } catch (e) {
    console.error("Failed to migrate anisette server setting", e);
  }
  const values: { [key: string]: unknown } = {};
  for (const key of await store.keys()) {
    values[key] = await store.get(key);
  }
  return values;
};
