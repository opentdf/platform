/** @jsxImportSource preact */
import { useMemo, useState } from "preact/hooks";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

function decodeBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export default function BindingPlayground() {
  const [dekHex, setDekHex] = useState(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  );
  const [policyB64, setPolicyB64] = useState("eyJ1dWlkIjoidGVzdCIsImJvZHkiOnt9fQ==");
  const [storedHashB64, setStoredHashB64] = useState("");

  const compute = useMemo(() => {
    try {
      const dek = hexToBytes(dekHex);
      const digest = hmac(sha256, dek, new TextEncoder().encode(policyB64));
      return { hex: bytesToHex(digest), b64: encodeBase64(digest), error: null as string | null };
    } catch (e) {
      return { hex: "", b64: "", error: (e as Error).message };
    }
  }, [dekHex, policyB64]);

  const verify = useMemo(() => {
    if (!storedHashB64) return null;
    try {
      const dek = hexToBytes(dekHex);
      const policyBytes = new TextEncoder().encode(policyB64);
      const expected = hmac(sha256, dek, policyBytes);
      let stored = decodeBase64(storedHashB64);
      let detectedHex = false;
      if (stored.length === 64) {
        const ascii = String.fromCharCode(...stored);
        if (/^[0-9a-fA-F]{64}$/.test(ascii)) {
          stored = hexToBytes(ascii);
          detectedHex = true;
        }
      }
      if (stored.length !== 32) {
        return { match: false, detail: `decoded length ${stored.length}, expected 32`, detectedHex };
      }
      let same = true;
      for (let i = 0; i < 32; i++) if (stored[i] !== expected[i]) same = false;
      return { match: same, detail: same ? "match" : "mismatch", detectedHex };
    } catch (e) {
      return { match: false, detail: (e as Error).message, detectedHex: false };
    }
  }, [dekHex, policyB64, storedHashB64]);

  return (
    <div class="space-y-4">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <label class="block text-sm">
          DEK share (hex, 32 bytes)
          <input
            class="w-full font-mono text-xs p-2 border rounded mt-1"
            value={dekHex}
            onInput={(e) => setDekHex((e.target as HTMLInputElement).value)}
          />
        </label>
        <label class="block text-sm">
          Canonical policy (base64-encoded policy JSON, byte-exact)
          <input
            class="w-full font-mono text-xs p-2 border rounded mt-1"
            value={policyB64}
            onInput={(e) => setPolicyB64((e.target as HTMLInputElement).value)}
          />
        </label>
      </div>

      <section class="border rounded p-3 bg-white">
        <h2 class="font-semibold text-sm">Computed binding</h2>
        {compute.error ? (
          <p class="text-red-700 text-sm mt-2">{compute.error}</p>
        ) : (
          <dl class="text-xs mt-2 space-y-1 font-mono">
            <div><dt class="inline text-slate-500">hex:&nbsp;</dt><dd class="inline break-all">{compute.hex}</dd></div>
            <div><dt class="inline text-slate-500">v4.4 base64:&nbsp;</dt><dd class="inline break-all">{compute.b64}</dd></div>
          </dl>
        )}
      </section>

      <section class="border rounded p-3 bg-white">
        <h2 class="font-semibold text-sm">Verify a stored binding</h2>
        <label class="block text-sm mt-2">
          stored hash (base64; legacy hex-then-base64 is auto-detected)
          <input
            class="w-full font-mono text-xs p-2 border rounded mt-1"
            value={storedHashB64}
            onInput={(e) => setStoredHashB64((e.target as HTMLInputElement).value)}
            placeholder="paste a policyBinding.hash value"
          />
        </label>
        {verify && (
          <p
            class={`mt-2 text-sm ${verify.match ? "text-emerald-700" : "text-red-700"}`}
          >
            {verify.match ? "✓ matches" : "✗"} {verify.detail}
            {verify.detectedHex && " (legacy hex-then-base64 detected)"}
          </p>
        )}
      </section>
    </div>
  );
}
