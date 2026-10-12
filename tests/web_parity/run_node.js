// Node driver for tests/test_web_analyzer.py.
//
// Reads one JSON request on stdin:
//   {"analyzer": "web/assets/analyzer.js", "now": "2026-10-12T00:00:00Z",
//    "files": [{"path": "...", "text": "..."}], "ciphers": ["HIGH:!aNULL", ...],
//    "cbom": {"timestamp": "...", "serialNumber": "..."}}
// and writes one JSON response on stdout:
//   {"version", "catalog", "cipherTable", "results": [analyze() per file],
//    "async": [analyzeAsync() per file], "ciphers": [[string, suites|null], ...],
//    "cbom": cbom(results)}
"use strict";

const path = require("path");

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on("data", (c) => chunks.push(c));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", reject);
  });
}

async function main() {
  const req = JSON.parse(await readStdin());
  const QS = require(path.resolve(req.analyzer));
  const opts = { now: req.now };
  const files = req.files || [];
  const results = files.map((f) => QS.analyze(f.path, f.text, opts));
  const asyncResults = [];
  for (const f of files) asyncResults.push(await QS.analyzeAsync(f.path, f.text, opts));
  const out = {
    version: QS.version,
    catalog: QS.catalog,
    cipherTable: QS.cipherTable,
    results,
    async: asyncResults,
    ciphers: (req.ciphers || []).map((s) => [s, QS.expandCipherString(s)]),
    cbom: req.cbom ? QS.cbom(results, req.cbom) : null,
  };
  process.stdout.write(JSON.stringify(out));
}

main().catch((e) => {
  process.stderr.write(String((e && e.stack) || e) + "\n");
  process.exit(1);
});
