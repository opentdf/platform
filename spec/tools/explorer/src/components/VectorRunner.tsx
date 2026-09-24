/** @jsxImportSource preact */
import { useEffect, useMemo, useState } from "preact/hooks";
import { VECTOR_INDEX, type VectorIndexEntry } from "@/data/vectors";
import { validateKao } from "@/lib/kao-runtime";

type FullVector = {
  id: string;
  description: string;
  conformance: string[];
  category: string;
  algorithm: string;
  inputs: Record<string, unknown>;
  expected: { outcome: "accept" | "reject"; errorCode?: string };
};

async function loadVector(file: string): Promise<FullVector> {
  const url = new URL(`/testvectors/kao/${file}`, import.meta.env.BASE_URL ?? "/");
  const res = await fetch(url);
  if (!res.ok) throw new Error(`failed to fetch ${url}`);
  return (await res.json()) as FullVector;
}

export default function VectorRunner() {
  const [filter, setFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(VECTOR_INDEX[0]?.id ?? null);
  const [vector, setVector] = useState<FullVector | null>(null);
  const [error, setError] = useState<string | null>(null);

  const list = useMemo(
    () => VECTOR_INDEX.filter((v) => v.id.includes(filter) || v.summary.includes(filter)),
    [filter],
  );

  useEffect(() => {
    if (!selectedId) return;
    const entry = VECTOR_INDEX.find((v) => v.id === selectedId);
    if (!entry) return;
    setError(null);
    setVector(null);
    loadVector(entry.file)
      .then(setVector)
      .catch((e: Error) => setError(e.message));
  }, [selectedId]);

  const result = useMemo(() => {
    if (!vector) return null;
    const kao = vector.inputs.kao as Record<string, unknown>;
    const r = validateKao(kao);
    const expected = vector.expected;
    if (expected.outcome === "accept") {
      return {
        passed: r.ok,
        detail: r.ok
          ? "structural ok"
          : `expected accept but errors: ${r.errors.map((e) => e.code).join(", ")}`,
      };
    }
    if (r.ok) {
      return { passed: false, detail: `expected reject (${expected.errorCode}) but no errors` };
    }
    const codes = r.errors.map((e) => e.code);
    return {
      passed: codes.includes(expected.errorCode ?? ""),
      detail: codes.includes(expected.errorCode ?? "")
        ? "rejected as expected"
        : `expected ${expected.errorCode} but got ${codes.join(", ")}`,
    };
  }, [vector]);

  return (
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
      <aside class="md:col-span-1">
        <input
          type="search"
          class="w-full p-2 text-sm border rounded mb-2"
          placeholder="filter vectors…"
          value={filter}
          onInput={(e) => setFilter((e.target as HTMLInputElement).value)}
        />
        <ul class="text-xs space-y-1 max-h-[600px] overflow-y-auto border rounded bg-white">
          {list.map((v) => (
            <li>
              <button
                type="button"
                onClick={() => setSelectedId(v.id)}
                class={`w-full text-left p-2 hover:bg-slate-100 ${selectedId === v.id ? "bg-sky-100" : ""}`}
              >
                <code class="font-semibold">{v.id}</code>
                <p class="text-slate-500">{v.summary}</p>
              </button>
            </li>
          ))}
        </ul>
      </aside>
      <section class="md:col-span-2 space-y-3">
        {error && <p class="text-red-700 text-sm">{error}</p>}
        {!vector && !error && <p class="text-slate-500 text-sm">loading…</p>}
        {vector && (
          <>
            <header class="border rounded p-3 bg-white">
              <h2 class="font-semibold">{vector.id}</h2>
              <p class="text-sm text-slate-600 mt-1">{vector.description}</p>
              <p class="text-xs text-slate-500 mt-2">
                Cat: {vector.category} • Alg: {vector.algorithm} • Conformance:{" "}
                {vector.conformance.join(", ")}
              </p>
            </header>
            {result && (
              <p
                class={`text-sm font-medium ${result.passed ? "text-emerald-700" : "text-red-700"}`}
              >
                {result.passed ? "✓" : "✗"} {result.detail}
              </p>
            )}
            <details>
              <summary class="text-sm cursor-pointer">vector inputs.kao</summary>
              <pre class="text-xs bg-slate-100 p-2 rounded overflow-x-auto">
                {JSON.stringify(vector.inputs.kao, null, 2)}
              </pre>
            </details>
            <details>
              <summary class="text-sm cursor-pointer">vector expected</summary>
              <pre class="text-xs bg-slate-100 p-2 rounded overflow-x-auto">
                {JSON.stringify(vector.expected, null, 2)}
              </pre>
            </details>
          </>
        )}
      </section>
    </div>
  );
}
