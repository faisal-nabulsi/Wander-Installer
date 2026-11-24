// Run with: bun test tests/
// New strings are added to en.json only. This checks that every other locale falls back to
// English for them, with the same options src/i18next.ts uses (fallbackLng: "en").
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createInstance } from "i18next";
import {
  errorSuggestionKeys,
  getErrorSuggestions,
  parseLinkToken,
} from "../src/errors";

const localesDir = join(import.meta.dir, "..", "src", "locales");
const resources = Object.fromEntries(
  readdirSync(localesDir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => [
      f.replace(/\.json$/, ""),
      { translation: JSON.parse(readFileSync(join(localesDir, f), "utf8")) },
    ]),
);

const makeT = async (lng: string) => {
  const i18n = createInstance();
  await i18n.init({
    lng,
    fallbackLng: "en",
    interpolation: { escapeValue: false },
    resources,
  });
  return i18n.t;
};

const twoFactorKeys = [
  "apple_id.two_factor_help_toggle",
  "apple_id.two_factor_help_step_airplane",
  "apple_id.two_factor_help_step_settings",
  "apple_id.two_factor_help_step_get_code",
  "apple_id.two_factor_help_step_type_code",
  "apple_id.two_factor_help_dont_retry",
  "apple_id.login_canceled",
  "apple_id.two_factor_help_scope",
  "apple_id.two_factor_help_sms",
];

describe("2FA help strings", () => {
  test("English text is exact", async () => {
    const t = await makeT("en");
    expect(t("apple_id.two_factor_help_toggle")).toBe("Didn't get a code?");
    expect(
      twoFactorKeys.slice(1, 5).map((k) => t(k)).join(" "),
    ).toBe(
      "On your iPhone, turn on Airplane Mode. Make sure Wi-Fi is off too. Open Settings > your name > Sign-In & Security. In the Account Details Unavailable pop-up, tap Get Verification Code. Type the code here, then turn Airplane Mode off.",
    );
    expect(t("apple_id.two_factor_help_dont_retry")).toBe(
      "Don't press Login again while you wait — each new attempt cancels the earlier code.",
    );
  });

  test("every locale, and a region code, falls back to English", async () => {
    const en = await makeT("en");
    const langs = [...Object.keys(resources), "de-DE", "xx"];
    for (const lng of langs) {
      const t = await makeT(lng);
      for (const key of twoFactorKeys) {
        expect(t(key)).toBe(en(key));
        expect(t(key)).not.toBe(key);
      }
    }
  });
});

describe("new error suggestions", () => {
  test("every suggestion key resolves in English", async () => {
    const t = await makeT("en");
    for (const keys of Object.values(errorSuggestionKeys)) {
      for (const key of keys) {
        const value = t(key, { returnObjects: true, defaultValue: [] });
        expect(Array.isArray(value)).toBe(true);
        expect((value as unknown[]).length).toBeGreaterThan(0);
      }
    }
  });

  test("-27589 guidance shows in a locale that lacks it", async () => {
    const t = await makeT("de");
    expect(
      getErrorSuggestions(t, "two_factor_rejected", "mac", "example.com"),
    ).toEqual([
      "Apple rejected the code. Close this, click Login once, and enter a fresh code.",
    ]);
    expect(
      getErrorSuggestions(t, "login_in_progress", "windows", "example.com"),
    ).toHaveLength(1);
    // Names no server: the deadline also covers the anisette server, not only Apple's.
    expect(
      getErrorSuggestions(t, "login_timed_out", "mac", "example.com"),
    ).toEqual([
      "The sign-in did not finish in time. Click Login again.",
      "If it keeps happening, check any VPN, firewall or network filter on this computer.",
    ]);
  });
});

describe("Apple account block suggestions", () => {
  const helpLink =
    "More about this error: ((link:https://wanderspoofer.com/help/install-errors/#apple-id-blocked))";

  test("0xe8008024 and 0xe8008018 guidance is exact, in a locale that lacks it", async () => {
    const t = await makeT("de");
    expect(
      getErrorSuggestions(t, "apple_id_blocked", "mac", "example.com"),
    ).toEqual([
      "Apple is refusing apps signed with this Apple ID on this device. This happens on Apple's side, and people using other sideloading tools report it too. Wander cannot fix it.",
      "Sign out and try a different Apple ID.",
      helpLink,
    ]);
    expect(
      getErrorSuggestions(t, "signing_identity_rejected", "windows", "example.com"),
    ).toEqual([
      "Apple no longer accepts the certificate that signed this app.",
      "Click Install Wander again. If it repeats, try a different Apple ID.",
      helpLink,
    ]);
  });

  test("every locale, and a region code, falls back to English", async () => {
    const en = await makeT("en");
    for (const lng of [...Object.keys(resources), "de-DE", "xx"]) {
      const t = await makeT(lng);
      for (const type of ["apple_id_blocked", "signing_identity_rejected"] as const) {
        expect(getErrorSuggestions(t, type, "linux", "example.com")).toEqual(
          getErrorSuggestions(en, type, "linux", "example.com"),
        );
      }
    }
  });

  test("the help link renders as one clickable link to the help page", () => {
    // Same split the error dialogs use (ErrorContext.tsx, OperationView.tsx).
    const parts = helpLink.split(/(\(\(link:[^)]+\)\)|\(\(link:[^)]+\)\))/g);
    const links = parts.map(parseLinkToken).filter((p) => p !== null);
    expect(links).toEqual([
      {
        url: "https://wanderspoofer.com/help/install-errors/#apple-id-blocked",
        text: "https://wanderspoofer.com/help/install-errors/#apple-id-blocked",
      },
    ]);
  });
});
