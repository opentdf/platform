// Browser-side mirror of basetdf_kao.validate. Structural-only; the crypto
// verifiers live in `kao-crypto.ts` and are invoked by VectorRunner when the
// user opts into the round-trip path.

import kaoSchema from "@spec/schema/BaseTDF/kao.schema.json";

export type ConformanceFinding = {
  code: string;
  conformanceId: string;
  path: string;
  message: string;
  severity: "error" | "warning";
};

export type ValidationReport = {
  ok: boolean;
  errors: ConformanceFinding[];
  warnings: ConformanceFinding[];
  normalized?: Record<string, unknown>;
};

const CANONICAL_ALGORITHMS = new Set([
  "RSA-OAEP",
  "RSA-OAEP-256",
  "ECDH-HKDF",
  "ML-KEM-768",
  "ML-KEM-1024",
  "X-ECDH-ML-KEM-768",
]);

const TYPE_TO_ALG: Record<string, string> = {
  wrapped: "RSA-OAEP",
  "ec-wrapped": "ECDH-HKDF",
};

const ALG_TO_TYPE: Record<string, string> = {
  "RSA-OAEP": "wrapped",
  "RSA-OAEP-256": "wrapped",
  "ECDH-HKDF": "ec-wrapped",
};

export function algorithmCategory(
  alg: string,
): "wrapping" | "agreement" | "encapsulation" | "hybrid" | undefined {
  switch (alg) {
    case "RSA-OAEP":
    case "RSA-OAEP-256":
      return "wrapping";
    case "ECDH-HKDF":
      return "agreement";
    case "ML-KEM-768":
    case "ML-KEM-1024":
      return "encapsulation";
    case "X-ECDH-ML-KEM-768":
      return "hybrid";
    default:
      return undefined;
  }
}

function err(
  code: string,
  conformanceId: string,
  path: string,
  message: string,
): ConformanceFinding {
  return { code, conformanceId, path, message, severity: "error" };
}

function warn(
  code: string,
  conformanceId: string,
  path: string,
  message: string,
): ConformanceFinding {
  return { code, conformanceId, path, message, severity: "warning" };
}

export function resolveAlgorithm(kao: Record<string, unknown>): string | undefined {
  if (typeof kao.alg === "string") return kao.alg;
  if (typeof kao.type === "string") return TYPE_TO_ALG[kao.type];
  return undefined;
}

export function validateKao(kao: Record<string, unknown>): ValidationReport {
  const errors: ConformanceFinding[] = [];
  const warnings: ConformanceFinding[] = [];

  // Required-field presence (KAO-C-002..005).
  const hasAlg = typeof kao.alg === "string" || typeof kao.type === "string";
  const hasKas = typeof kao.kas === "string" || typeof kao.url === "string";
  const hasProtected =
    typeof kao.protectedKey === "string" || typeof kao.wrappedKey === "string";

  if (!hasAlg)
    errors.push(
      err("kao.missing_required_field", "KAO-C-002", "/alg", "neither alg nor type is present"),
    );
  if (!hasKas)
    errors.push(
      err("kao.missing_required_field", "KAO-C-003", "/kas", "neither kas nor url is present"),
    );
  if (!hasProtected)
    errors.push(
      err(
        "kao.missing_required_field",
        "KAO-C-004",
        "/protectedKey",
        "neither protectedKey nor wrappedKey is present",
      ),
    );
  if (!("policyBinding" in kao))
    errors.push(
      err("kao.policy_binding_missing", "KAO-C-005", "/policyBinding", "policyBinding is required"),
    );

  // alg enum (KAO-C-010).
  if (typeof kao.alg === "string" && !CANONICAL_ALGORITHMS.has(kao.alg))
    errors.push(err("kao.unknown_alg", "KAO-C-010", "/alg", `unknown alg: ${kao.alg}`));

  // alg/type conflict (KAO-C-020).
  if (typeof kao.alg === "string" && typeof kao.type === "string") {
    const expectedType = ALG_TO_TYPE[kao.alg];
    if (expectedType !== undefined && expectedType !== kao.type) {
      errors.push(
        err(
          "kao.alg_type_conflict",
          "KAO-C-020",
          "/type",
          `alg=${kao.alg} and type=${kao.type} disagree`,
        ),
      );
    } else if (expectedType === undefined && kao.type !== "") {
      errors.push(
        err(
          "kao.alg_type_conflict",
          "KAO-C-020",
          "/type",
          `alg=${kao.alg} has no v4.3 type equivalent`,
        ),
      );
    }
  }

  // alias conflicts (KAO-C-021..023).
  if (
    typeof kao.kas === "string" &&
    typeof kao.url === "string" &&
    kao.kas !== kao.url
  )
    errors.push(
      err(
        "kao.alias_conflict",
        "KAO-C-021",
        "/url",
        "kas and url present with different values",
      ),
    );

  if (
    typeof kao.protectedKey === "string" &&
    typeof kao.wrappedKey === "string" &&
    kao.protectedKey !== kao.wrappedKey
  )
    errors.push(
      err(
        "kao.alias_conflict",
        "KAO-C-022",
        "/wrappedKey",
        "protectedKey and wrappedKey present with different values",
      ),
    );

  if (
    typeof kao.ephemeralKey === "string" &&
    typeof kao.ephemeralPublicKey === "string" &&
    kao.ephemeralKey !== kao.ephemeralPublicKey
  )
    errors.push(
      err(
        "kao.alias_conflict",
        "KAO-C-023",
        "/ephemeralPublicKey",
        "ephemeralKey and ephemeralPublicKey present with different values",
      ),
    );

  // Conditional fields by algorithm (KAO-C-030/031).
  const resolved = resolveAlgorithm(kao);
  const ephemeralPresent =
    typeof kao.ephemeralKey === "string" || typeof kao.ephemeralPublicKey === "string";
  if (resolved !== undefined) {
    const cat = algorithmCategory(resolved);
    if (
      (cat === "agreement" || cat === "encapsulation" || cat === "hybrid") &&
      !ephemeralPresent
    ) {
      errors.push(
        err(
          "kao.ephemeral_key_required",
          "KAO-C-030",
          "/ephemeralKey",
          `ephemeralKey is required for alg=${resolved}`,
        ),
      );
    } else if (cat === "wrapping" && ephemeralPresent) {
      warnings.push(
        warn(
          "kao.ephemeral_key_unexpected",
          "KAO-C-031",
          "/ephemeralKey",
          `ephemeralKey is unexpected for alg=${resolved}`,
        ),
      );
    }
  }

  // policyBinding shape (KAO-C-014, KAO-C-202).
  const pb = kao.policyBinding;
  if (pb !== undefined) {
    if (typeof pb === "object" && pb !== null && !Array.isArray(pb)) {
      const o = pb as Record<string, unknown>;
      const allowed = new Set(["alg", "hash"]);
      for (const k of Object.keys(o)) {
        if (!allowed.has(k)) {
          errors.push(
            err(
              "kao.schema_violation",
              "KAO-C-014",
              "/policyBinding",
              `policyBinding has unknown property: ${k}`,
            ),
          );
        }
      }
      if (typeof o.alg === "string" && o.alg !== "HS256") {
        errors.push(
          err(
            "kao.policy_binding_alg_unsupported",
            "KAO-C-202",
            "/policyBinding/alg",
            `policyBinding.alg=${o.alg} is unsupported`,
          ),
        );
      }
    } else if (typeof pb === "string") {
      warnings.push(
        warn(
          "kao.policy_binding_format_invalid",
          "KAO-C-204",
          "/policyBinding",
          "policyBinding is a bare string; v4.4 producers MUST emit the object form",
        ),
      );
    } else {
      errors.push(
        err(
          "kao.policy_binding_format_invalid",
          "KAO-C-005",
          "/policyBinding",
          "policyBinding is neither a valid object nor a string",
        ),
      );
    }
  }

  // additional top-level properties (KAO-C-013).
  const allowedTop = new Set(Object.keys(kaoSchema.properties));
  for (const k of Object.keys(kao)) {
    if (!allowedTop.has(k))
      errors.push(
        err("kao.schema_violation", "KAO-C-013", `/${k}`, `unknown top-level property: ${k}`),
      );
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    normalized: errors.length === 0 ? normalize(kao) : undefined,
  };
}

export function normalize(kao: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const alg = resolveAlgorithm(kao);
  if (alg !== undefined) out.alg = alg;
  const kas = (kao.kas as string | undefined) ?? (kao.url as string | undefined);
  if (kas !== undefined) out.kas = kas;
  if (typeof kao.kid === "string") out.kid = kao.kid;
  if (typeof kao.sid === "string") out.sid = kao.sid;
  const pk =
    (kao.protectedKey as string | undefined) ?? (kao.wrappedKey as string | undefined);
  if (pk !== undefined) out.protectedKey = pk;
  const ek =
    (kao.ephemeralKey as string | undefined) ?? (kao.ephemeralPublicKey as string | undefined);
  if (ek !== undefined) out.ephemeralKey = ek;
  if (typeof kao.policyBinding === "object" && kao.policyBinding !== null) {
    out.policyBinding = kao.policyBinding;
  } else if (typeof kao.policyBinding === "string") {
    out.policyBinding = { alg: "HS256", hash: kao.policyBinding };
  }
  if (typeof kao.encryptedMetadata === "string")
    out.encryptedMetadata = kao.encryptedMetadata;
  return out;
}
