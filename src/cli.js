import { parseArgs } from "node:util";

import { audit, diff } from "./audit.js";
import { decide, InputError, readPolicy, request, scenario } from "./policy.js";

const USAGE = `AksesLab · simulator dan auditor aturan akses

node src/cli.js validate KEBIJAKAN.json [--json]
node src/cli.js explain KEBIJAKAN.json --resource NAMA --action AKSI
                    [--role NAMA ...] [--owner] [--same-unit] [--json]
node src/cli.js audit KEBIJAKAN.json [--limit 0–20] [--json]
node src/cli.js diff SEBELUM.json SESUDAH.json [--limit 0–20] [--json]

Opsi --role dapat diulang. Tanpa role berarti anonim.
Opsi --limit membatasi contoh, dengan nilai bawaan 5.
Kode keluar 0 untuk lolos, 1 untuk temuan audit atau izin baru, 2 untuk kesalahan masukan.`;

const BOOLEAN = { type: "boolean" };
const STRING = { type: "string" };
const OPTIONS = {
  validate: {},
  explain: {
    resource: STRING, action: STRING, role: { type: "string", multiple: true },
    owner: BOOLEAN, "same-unit": BOOLEAN,
  },
  audit: { limit: STRING },
  diff: { limit: STRING },
};
const REASONS = {
  "explicit-deny": "Ada aturan penolakan yang cocok.",
  "matched-allow": "Ada aturan pemberian izin yang cocok.",
  "default-deny": "Tidak ada aturan izin yang cocok.",
};

function parse(mode, argv) {
  let args;
  try {
    args = parseArgs({
      args: argv, allowPositionals: true, tokens: true,
      options: { ...OPTIONS[mode], json: BOOLEAN, help: BOOLEAN },
    });
  } catch (error) {
    throw new InputError(`Argumen tidak valid (${error.message}). Gunakan --help.`);
  }
  const seen = new Set();
  for (const token of args.tokens) {
    if (token.kind !== "option" || token.name === "role") continue;
    if (seen.has(token.name)) throw new InputError(`Opsi --${token.name} berulang.`);
    seen.add(token.name);
  }
  return args;
}

function exampleLimit(value = "5") {
  if (!/^(?:[0-9]|1[0-9]|20)$/.test(value)) {
    throw new InputError("--limit harus bilangan bulat dari 0 sampai 20.");
  }
  return Number(value);
}

function showScenario(item) {
  const roles = item.roles.join(" + ") || "anonim";
  return `${item.resource}/${item.action} · ${roles} · owner=${item.owner} · sameUnit=${item.sameUnit}`;
}

function textReport(report) {
  if (report.mode === "validate") {
    return `Kebijakan valid · ${report.roles} role · ${report.capabilities} pasangan aksi · ${report.rules} aturan · ${report.checks} pemeriksaan`;
  }
  if (report.mode === "explain") {
    return [
      showScenario(report),
      `Role efektif · ${report.effectiveRoles.join(", ") || "anonim"}`,
      `Keputusan ${report.decision} · ${REASONS[report.reason]}`,
      `Aturan allow · ${report.matched.allow.join(", ") || "—"}`,
      `Aturan deny · ${report.matched.deny.join(", ") || "—"}`,
    ].join("\n");
  }
  if (report.mode === "audit") {
    const lines = [
      `${report.evaluated} dari ${report.possible} skenario tercakup · ${report.assertions} evaluasi pemeriksaan · ${report.violations} pelanggaran · ${report.emptyChecks} pemeriksaan tanpa cakupan`,
    ];
    for (const row of report.checks) {
      lines.push(`${row.id} · ${row.status.toUpperCase()} · ${row.failed}/${row.tested} melanggar`);
      for (const example of row.examples) {
        lines.push(`  ${showScenario(example)} → ${example.decision}, harapan ${row.expect}`);
        lines.push(`  Aturan cocok · allow=${example.matched.allow.join(", ") || "—"} · deny=${example.matched.deny.join(", ") || "—"}`);
      }
    }
    return lines.join("\n");
  }
  const lines = [
    `${report.evaluated} skenario · ${report.gained.count} izin baru · ${report.lost.count} izin dicabut · ${report.unchanged} tetap`,
  ];
  for (const [label, bucket] of [["Izin baru", report.gained], ["Izin dicabut", report.lost]]) {
    for (const example of bucket.examples) {
      lines.push(`${label} · ${showScenario(example)} · ${example.before.decision} → ${example.after.decision}`);
    }
  }
  return lines.join("\n");
}

function main(argv) {
  const [mode, ...rest] = argv;
  if (mode === undefined || mode === "--help") {
    console.log(USAGE);
    return 0;
  }
  try {
    if (!Object.hasOwn(OPTIONS, mode)) throw new InputError("Pilih validate, explain, audit, atau diff.");
    const { values, positionals } = parse(mode, rest);
    if (values.help) {
      console.log(USAGE);
      return 0;
    }
    const expected = mode === "diff" ? 2 : 1;
    if (positionals.length !== expected) throw new InputError(`Perintah ${mode} memerlukan ${expected} path kebijakan.`);
    const model = readPolicy(positionals[0]);
    let report;
    if (mode === "validate") {
      report = {
        schemaVersion: 1, mode, roles: model.roleNames.length, capabilities: model.capabilities.size,
        rules: model.ruleCount, checks: model.checks.length,
      };
    } else if (mode === "explain") {
      const { capability, mask, bits } = request(model, {
        resource: values.resource, action: values.action, roles: values.role ?? [],
        owner: values.owner ?? false, sameUnit: values["same-unit"] ?? false,
      });
      report = { schemaVersion: 1, mode, ...scenario(model, capability, mask, bits), ...decide(model, capability, mask, bits) };
    } else if (mode === "audit") {
      report = audit(model, exampleLimit(values.limit));
    } else {
      report = diff(model, readPolicy(positionals[1]), exampleLimit(values.limit));
    }
    console.log(values.json ? JSON.stringify(report, null, 2) : textReport(report));
    return report.passed === false ? 1 : 0;
  } catch (error) {
    if (!(error instanceof InputError)) throw error;
    console.error(`Gagal. ${error.message}`);
    return 2;
  }
}

process.exitCode = main(process.argv.slice(2));
