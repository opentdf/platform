import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { validateKao } from "../src/lib/kao-runtime";
import { VECTOR_INDEX } from "../src/data/vectors";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(__dirname, "..", "..", "..", "testvectors", "kao");

type Vector = {
  id: string;
  category: string;
  inputs: { kao: Record<string, unknown> };
  expected: { outcome: "accept" | "reject"; errorCode?: string };
};

function loadVector(file: string): Vector {
  return JSON.parse(readFileSync(join(VECTORS_DIR, file), "utf-8")) as Vector;
}

describe("KAO conformance vectors (browser-side validator)", () => {
  // The browser-side validator covers structural assertions but does not
  // run policy-binding HMAC verification. Vectors whose only failure mode is
  // a binding/AEAD/KEM cryptographic check are covered by the Python harness
  // (`basetdf-kao run-vectors`); they're excluded here.
  const cryptoOnlyErrors = new Set([
    "kao.policy_binding_mismatch",
    "kao.aead_tag_failure",
    "kao.kem_decapsulation_failure",
    "kao.metadata_decrypt_failure",
    "kao.split_reconstruction_failure",
  ]);
  const structuralCategories = new Set(["positive", "negative", "legacy"]);
  const cases = VECTOR_INDEX.filter((v) => structuralCategories.has(v.category))
    .filter((v) => {
      try {
        readFileSync(join(VECTORS_DIR, v.file));
        return true;
      } catch {
        return false;
      }
    })
    .filter((v) => {
      const ec = loadVector(v.file).expected.errorCode;
      return !ec || !cryptoOnlyErrors.has(ec);
    });

  it.each(cases)("$id ($category)", (entry) => {
    const v = loadVector(entry.file);
    const report = validateKao(v.inputs.kao);
    if (v.expected.outcome === "accept") {
      expect(report.errors, `expected accept for ${v.id}`).toEqual([]);
      return;
    }
    const codes = report.errors.map((f) => f.code);
    expect(codes, `expected reject (${v.expected.errorCode}) for ${v.id}`).toContain(
      v.expected.errorCode,
    );
  });
});
