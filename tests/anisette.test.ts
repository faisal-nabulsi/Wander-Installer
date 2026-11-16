// Run with: bun test tests/
// Kept outside src/ so `tsc` (which only includes src/) does not need bun's types.
import { describe, expect, test } from "bun:test";
import {
  ANISETTE_SERVERS,
  ANISETTE_SERVER_KEY,
  DEFAULT_ANISETTE_SERVER,
  KNOWN_BAD_ANISETTE_SERVERS,
  LEGACY_ANISETTE_SERVER_KEY,
  migrateAnisetteServerKey,
  migrateLegacyAnisetteServer,
  normalizeAnisetteHost,
  readInitialStoreValues,
} from "../src/anisette";

class FakeStore {
  values: Record<string, unknown>;
  saves = 0;
  constructor(values: Record<string, unknown>) {
    this.values = { ...values };
  }
  async get<T>(key: string): Promise<T | undefined> {
    return this.values[key] as T | undefined;
  }
  async set(key: string, value: unknown) {
    this.values[key] = value;
  }
  async save() {
    this.saves += 1;
  }
  async keys(): Promise<string[]> {
    return Object.keys(this.values);
  }
}

describe("anisette presets", () => {
  test("default is mac-ani.jkcoxson.com and is a preset", () => {
    expect(DEFAULT_ANISETTE_SERVER).toBe("mac-ani.jkcoxson.com");
    expect(ANISETTE_SERVERS.map(([v]) => v)).toContain(DEFAULT_ANISETTE_SERVER);
  });

  test("exactly the four Mac-backed servers, none of them known-bad", () => {
    expect(ANISETTE_SERVERS.map(([v]) => v)).toEqual([
      "mac-ani.jkcoxson.com",
      "ani.iloader.app",
      "new.ani.sidestore.io",
      "ani3.stikstore.app",
    ]);
    for (const [value] of ANISETTE_SERVERS) {
      expect(KNOWN_BAD_ANISETTE_SERVERS).not.toContain(value);
    }
  });

  test("store key was renamed", () => {
    expect(ANISETTE_SERVER_KEY).not.toBe(LEGACY_ANISETTE_SERVER_KEY);
  });
});

describe("normalizeAnisetteHost", () => {
  test("strips scheme, case and trailing slash", () => {
    expect(normalizeAnisetteHost(" HTTPS://Ani.846969.xyz/ ")).toBe("ani.846969.xyz");
    expect(normalizeAnisetteHost("http://my.server:6969")).toBe("my.server:6969");
  });
});

describe("migrateLegacyAnisetteServer", () => {
  // The preset list of 2.3.2 (dd16173 src/pages/Settings.tsx), hard-coded so that
  // dropping one from KNOWN_BAD_ANISETTE_SERVERS fails this test.
  const PRESETS_2_3_2 = [
    "ani.sidestore.io",
    "ani.stikstore.app",
    "ani.sidestore.app",
    "ani.sidestore.zip",
    "ani.846969.xyz",
    "ani.neoarz.xyz",
    "ani.xu30.top",
    "anisette.wedotstud.io",
  ];

  test("old default and every 2.3.2 preset fall back to the new default", () => {
    for (const old of PRESETS_2_3_2) {
      expect(migrateLegacyAnisetteServer(old)).toBeNull();
      expect(migrateLegacyAnisetteServer(`https://${old}/`)).toBeNull();
    }
  });

  test("every known-bad server falls back to the new default", () => {
    for (const bad of [...KNOWN_BAD_ANISETTE_SERVERS, "ani.npeg.us"]) {
      expect(migrateLegacyAnisetteServer(bad)).toBeNull();
    }
  });

  test("a user's own custom server is kept", () => {
    expect(migrateLegacyAnisetteServer("ani.example.org")).toBe("ani.example.org");
    expect(migrateLegacyAnisetteServer("http://192.168.1.5:6969")).toBe(
      "http://192.168.1.5:6969",
    );
  });

  test("a custom entry that is already a new preset is kept", () => {
    expect(migrateLegacyAnisetteServer("ani.iloader.app")).toBe("ani.iloader.app");
  });

  test("missing, empty or non-string values are dropped", () => {
    expect(migrateLegacyAnisetteServer(undefined)).toBeNull();
    expect(migrateLegacyAnisetteServer(null)).toBeNull();
    expect(migrateLegacyAnisetteServer("  ")).toBeNull();
    expect(migrateLegacyAnisetteServer(42)).toBeNull();
  });
});

describe("migrateAnisetteServerKey", () => {
  test("fresh install: writes nothing, default applies", async () => {
    const store = new FakeStore({});
    expect(await migrateAnisetteServerKey(store)).toBeNull();
    expect(store.values[ANISETTE_SERVER_KEY]).toBeUndefined();
    expect(store.saves).toBe(0);
  });

  test("2.3.2 install on the old default: writes nothing, default applies", async () => {
    const store = new FakeStore({ [LEGACY_ANISETTE_SERVER_KEY]: "ani.846969.xyz" });
    expect(await migrateAnisetteServerKey(store)).toBeNull();
    expect(store.values[ANISETTE_SERVER_KEY]).toBeUndefined();
  });

  test("2.3.2 install with a good custom server: carried over once", async () => {
    const store = new FakeStore({ [LEGACY_ANISETTE_SERVER_KEY]: "ani.example.org" });
    expect(await migrateAnisetteServerKey(store)).toBe("ani.example.org");
    expect(store.values[ANISETTE_SERVER_KEY]).toBe("ani.example.org");
    expect(store.saves).toBe(1);
  });

  test("new key already set: never overwritten", async () => {
    const store = new FakeStore({
      [LEGACY_ANISETTE_SERVER_KEY]: "ani.example.org",
      [ANISETTE_SERVER_KEY]: "ani3.stikstore.app",
    });
    expect(await migrateAnisetteServerKey(store)).toBeNull();
    expect(store.values[ANISETTE_SERVER_KEY]).toBe("ani3.stikstore.app");
    expect(store.saves).toBe(0);
  });
});

describe("readInitialStoreValues (StoreProvider start-up)", () => {
  test("migrates before reading, so the custom server is visible under the new key", async () => {
    const store = new FakeStore({
      [LEGACY_ANISETTE_SERVER_KEY]: "ani.example.org",
      theme: "dark",
    });
    const values = await readInitialStoreValues(store);
    expect(values[ANISETTE_SERVER_KEY]).toBe("ani.example.org");
    expect(values.theme).toBe("dark");
  });

  test("an old preset leaves the new key unset, so the default applies", async () => {
    const store = new FakeStore({ [LEGACY_ANISETTE_SERVER_KEY]: "ani.846969.xyz" });
    const values = await readInitialStoreValues(store);
    expect(values[ANISETTE_SERVER_KEY]).toBeUndefined();
  });

  test("a failing migration does not block start-up", async () => {
    const store = new FakeStore({ theme: "dark" });
    let first = true;
    store.get = async <T>(key: string) => {
      if (first) {
        first = false;
        throw new Error("boom");
      }
      return store.values[key] as T | undefined;
    };
    const original = console.error;
    console.error = () => {};
    try {
      const values = await readInitialStoreValues(store);
      expect(values.theme).toBe("dark");
    } finally {
      console.error = original;
    }
  });
});
