/** @jsxImportSource preact */
import { useMemo, useState } from "preact/hooks";
import { validateKao, type ValidationReport } from "@/lib/kao-runtime";

const SAMPLE = `{
  "alg": "RSA-OAEP-256",
  "kas": "https://kas.example.com",
  "kid": "rsa-2048-test",
  "sid": "s-0",
  "protectedKey": "...",
  "policyBinding": { "alg": "HS256", "hash": "..." }
}`;

export default function KAOInspector() {
  const [text, setText] = useState(SAMPLE);

  const result = useMemo<{ report?: ValidationReport; parseError?: string }>(() => {
    try {
      const obj = JSON.parse(text);
      if (typeof obj !== "object" || obj === null)
        return { parseError: "input must be a JSON object" };
      return { report: validateKao(obj as Record<string, unknown>) };
    } catch (e) {
      return { parseError: (e as Error).message };
    }
  }, [text]);

  return (
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <label class="block text-sm font-medium mb-1">KAO JSON</label>
        <textarea
          class="w-full h-96 font-mono text-xs p-3 border rounded bg-white"
          value={text}
          onInput={(e) => setText((e.target as HTMLTextAreaElement).value)}
        />
      </div>
      <div class="space-y-3">
        <h2 class="font-semibold text-sm">Validation</h2>
        {result.parseError && (
          <p class="text-red-700 text-sm">{result.parseError}</p>
        )}
        {result.report && (
          <>
            <p class={`text-sm ${result.report.ok ? "text-emerald-700" : "text-red-700"}`}>
              {result.report.ok ? "✓ structurally valid" : "✗ rejected"}
            </p>
            {result.report.errors.length > 0 && (
              <ul class="text-xs space-y-2">
                {result.report.errors.map((f) => (
                  <li class="border-l-2 border-red-400 bg-red-50 p-2">
                    <code class="font-semibold">{f.conformanceId}</code>{" "}
                    <code class="text-red-700">{f.code}</code>
                    <p class="text-slate-600 mt-1">{f.path}: {f.message}</p>
                  </li>
                ))}
              </ul>
            )}
            {result.report.warnings.length > 0 && (
              <ul class="text-xs space-y-2">
                {result.report.warnings.map((f) => (
                  <li class="border-l-2 border-amber-400 bg-amber-50 p-2">
                    <code class="font-semibold">{f.conformanceId}</code>{" "}
                    <code class="text-amber-700">{f.code}</code>
                    <p class="text-slate-600 mt-1">{f.path}: {f.message}</p>
                  </li>
                ))}
              </ul>
            )}
            {result.report.normalized && (
              <details>
                <summary class="text-sm cursor-pointer">v4.4 normalised form</summary>
                <pre class="text-xs bg-slate-100 p-2 rounded mt-2 overflow-x-auto">
                  {JSON.stringify(result.report.normalized, null, 2)}
                </pre>
              </details>
            )}
          </>
        )}
      </div>
    </div>
  );
}
