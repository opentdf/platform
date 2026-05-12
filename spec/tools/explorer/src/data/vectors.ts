// Build-time imports of the test-vector index. Vectors themselves are loaded
// dynamically at runtime by the VectorRunner component via fetch().

import index from "@spec/testvectors/kao/index.json";

export type VectorIndexEntry = {
  id: string;
  file: string;
  category: "positive" | "negative" | "legacy" | "kat";
  algorithm: string;
  conformance: string[];
  summary: string;
};

export const VECTOR_INDEX: VectorIndexEntry[] = index.vectors as VectorIndexEntry[];
export const SPEC_VERSION: string = (index as { specVersion: string }).specVersion;
