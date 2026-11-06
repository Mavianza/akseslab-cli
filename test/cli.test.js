import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const SAFE = "examples/kebijakan-aman.json";
const LOOSE = "examples/kebijakan-longgar.json";
const SAMPLE = JSON.parse(readFileSync(join(ROOT, SAFE), "utf8"));

function cli(...args) {
  const result = spawnSync(process.execPath, ["src/cli.js", ...args], {
    cwd: ROOT, encoding: "utf8", timeout: 15_000,
  });
  if (result.error) throw result.error;
  return result;
}

function resultJSON(status, ...args) {
  const result = cli(...args, "--json");
  assert.equal(result.status, status, result.stderr || result.stdout);
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

function withFiles(t) {
  const temp = mkdtempSync(join(tmpdir(), "akseslab-test-"));
  t.after(() => rmSync(temp, { recursive: true, force: true }));
  return (name, content) => {
    const path = join(temp, name);
    writeFileSync(path, Buffer.isBuffer(content) || typeof content === "string" ? content : JSON.stringify(content));
    return path;
  };
}

function expectInputError(pattern, ...args) {
  const result = cli(...args, "--json");
  assert.equal(result.status, 2, result.stderr || result.stdout);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, pattern);
}

function minimalPolicy() {
  return { version: 1, roles: { staf: [] }, resources: { dokumen: ["baca"] }, rules: [] };
}

test("validasi sampel mengenali jumlah role, aturan, aksi, dan pemeriksaan", () => {
  assert.deepEqual(resultJSON(0, "validate", SAFE), {
    schemaVersion: 1, mode: "validate", roles: 3, capabilities: 3, rules: 5, checks: 5,
  });
});

test("audit sampel aman mencakup akses wali, pewarisan, dan anonim", () => {
  const report = resultJSON(0, "audit", SAFE);
  assert.equal(report.passed, true);
  assert.equal(report.possible, 87);
  assert.equal(report.evaluated, 27);
  assert.equal(report.assertions, 27);
  assert.equal(report.violations, 0);
  assert.equal(report.emptyChecks, 0);
  assert.equal(report.checks.length, 5);
  assert.ok(report.checks.every(check => check.status === "pass" && check.tested > 0));
});

test("audit menemukan tiga izin bocor yang baru muncul pada gabungan role", () => {
  const report = resultJSON(1, "audit", LOOSE);
  assert.equal(report.passed, false);
  assert.equal(report.evaluated, 27);
  assert.equal(report.violations, 3);
  const check = report.checks.find(item => item.id === "wali-tolak-dokumen-lain");
  assert.equal(check.tested, 8);
  assert.equal(check.failed, 3);
  assert.deepEqual(check.examples.map(example => example.roles), [
    ["asisten", "wali"], ["koordinator", "wali"], ["asisten", "koordinator", "wali"],
  ]);
  for (const example of check.examples) {
    assert.equal(example.owner, false);
    assert.equal(example.sameUnit, true);
    assert.equal(example.decision, "allow");
    assert.deepEqual(example.matched.allow, ["asisten-baca-unit"]);
  }
  const singleRole = resultJSON(0, "explain", LOOSE, "--resource", "dokumen", "--action", "baca", "--role", "wali", "--same-unit");
  assert.equal(singleRole.reason, "default-deny");
});

test("explain memperlihatkan role efektif dan deny menang atas izin yang cocok", () => {
  const result = resultJSON(0, "explain", SAFE, "--resource", "dokumen", "--action", "baca",
    "--role", "wali", "--role", "koordinator", "--same-unit");
  assert.deepEqual(result.roles, ["koordinator", "wali"]);
  assert.deepEqual(result.effectiveRoles, ["asisten", "koordinator", "wali"]);
  assert.equal(result.decision, "deny");
  assert.equal(result.reason, "explicit-deny");
  assert.deepEqual(result.matched, { allow: ["asisten-baca-unit"], deny: ["wali-tolak-bukan-milik"] });
});

test("keputusan anonim menolak secara default, wildcard dapat membuka aksi tertentu", () => {
  const deny = resultJSON(0, "explain", SAFE, "--resource", "dokumen", "--action", "baca");
  const allow = resultJSON(0, "explain", SAFE, "--resource", "pengumuman", "--action", "baca");
  assert.deepEqual(deny.roles, []);
  assert.equal(deny.reason, "default-deny");
  assert.equal(allow.decision, "allow");
  assert.deepEqual(allow.matched.allow, ["pengumuman-umum"]);
});

test("pewarisan transitif menyatukan induk bersama tanpa role ganda", t => {
  const make = withFiles(t);
  const path = make("diamond.json", {
    ...minimalPolicy(),
    roles: { senior: ["editor", "mentor"], mentor: ["dasar"], editor: ["dasar"], dasar: [] },
    rules: [{ id: "dasar-baca", effect: "allow", roles: ["dasar"], resource: "dokumen", actions: ["baca"] }],
  });
  const result = resultJSON(0, "explain", path, "--resource", "dokumen", "--action", "baca", "--role", "senior");
  assert.equal(result.decision, "allow");
  assert.deepEqual(result.effectiveRoles, ["dasar", "editor", "mentor", "senior"]);
});

test("diff memeriksa seluruh 87 skenario dan menghitung izin baru serta pencabutan", () => {
  const gained = resultJSON(1, "diff", SAFE, LOOSE, "--limit", "1");
  assert.equal(gained.evaluated, 87);
  assert.equal(gained.unchanged, 84);
  assert.equal(gained.gained.count, 3);
  assert.equal(gained.gained.examples.length, 1);
  assert.equal(gained.lost.count, 0);
  assert.deepEqual(gained.gained.examples[0].roles, ["asisten", "wali"]);
  assert.equal(gained.gained.examples[0].before.reason, "explicit-deny");
  assert.equal(gained.gained.examples[0].after.reason, "matched-allow");
  const lost = resultJSON(0, "diff", LOOSE, SAFE);
  assert.equal(lost.lost.count, 3);
  assert.equal(lost.gained.count, 0);
  assert.equal(lost.passed, true);
});

test("diff mendeteksi izin baru dari perubahan pewarisan", t => {
  const make = withFiles(t);
  const original = make("awal.json", {
    ...minimalPolicy(),
    roles: { dasar: [], ketua: [] },
    rules: [{ id: "dasar-baca", effect: "allow", roles: ["dasar"], resource: "dokumen", actions: ["baca"] }],
  });
  const revised = make("revisi.json", {
    ...minimalPolicy(),
    roles: { ketua: ["dasar"], dasar: [] },
    rules: [{ id: "dasar-baca", effect: "allow", roles: ["dasar"], resource: "dokumen", actions: ["baca"] }],
  });
  const report = resultJSON(1, "diff", original, revised);
  assert.equal(report.gained.count, 4);
  assert.ok(report.gained.examples.every(example => example.roles.join() === "ketua"));
  assert.deepEqual(report.gained.examples[0].after.effectiveRoles, ["dasar", "ketua"]);
});

test("audit dengan limit nol tetap menghitung semua pelanggaran", () => {
  const report = resultJSON(1, "audit", LOOSE, "--limit", "0");
  assert.equal(report.violations, 3);
  assert.ok(report.checks.every(check => check.examples.length === 0));
});

test("urutan deklarasi tidak mengubah byte laporan atau berkas kebijakan", t => {
  const make = withFiles(t);
  const before = structuredClone(SAMPLE);
  before.rules = before.rules.filter(rule => rule.effect !== "deny");
  const reverseEntries = obj => Object.fromEntries(Object.entries(obj).reverse());
  const after = {
    ...before,
    roles: reverseEntries(before.roles),
    resources: reverseEntries(before.resources),
    rules: [...before.rules].reverse(),
    checks: [...before.checks].reverse(),
  };
  const left = make("kiri.json", before);
  const right = make("kanan.json", after);
  const originalBytes = readFileSync(right);
  const lhs = cli("audit", left, "--json");
  const rhs = cli("audit", right, "--json");
  assert.equal(lhs.status, 1);
  assert.equal(rhs.status, 1);
  assert.equal(lhs.stdout, rhs.stdout);
  assert.deepEqual(readFileSync(right), originalBytes);
});

test("semesta dengan sepuluh role dan relasi lengkap diuji tanpa sampling", t => {
  const make = withFiles(t);
  const path = make("semesta.json", {
    ...minimalPolicy(),
    roles: Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`role-${i}`, []])),
    checks: [{ id: "tidak-ada-izin", resource: "dokumen", actions: ["baca"], expect: "deny" }],
  });
  const report = resultJSON(0, "audit", path);
  assert.equal(report.evaluated, 1 + 4 * (2 ** 10 - 1));
  assert.equal(report.possible, report.evaluated);
  assert.equal(report.checks[0].tested, 4093);
  assert.equal(report.violations, 0);
});

test("kebijakan anonim murni mendukung satu skenario per aksi", t => {
  const make = withFiles(t);
  const path = make("anonim.json", {
    ...minimalPolicy(), roles: {},
    checks: [{ id: "anon-tolak", resource: "dokumen", actions: ["baca"], expect: "deny", subject: { anonymous: true } }],
  });
  const report = resultJSON(0, "audit", path);
  assert.equal(report.evaluated, 1);
  assert.equal(report.checks[0].status, "pass");
});

test("pemeriksaan tanpa skenario yang cocok gagal, termasuk relasi anonim mustahil", t => {
  const make = withFiles(t);
  const path = make("kosong.json", {
    ...minimalPolicy(),
    checks: [
      { id: "kontradiksi", resource: "dokumen", actions: ["baca"], expect: "deny",
        subject: { allRoles: ["staf"], noRoles: ["staf"] } },
      { id: "anonim-milik", resource: "dokumen", actions: ["baca"], expect: "deny",
        subject: { anonymous: true }, when: { owner: true } },
    ],
  });
  const report = resultJSON(1, "audit", path);
  assert.equal(report.violations, 0);
  assert.equal(report.emptyChecks, 2);
  assert.ok(report.checks.every(check => check.status === "empty"));
});

test("audit menolak kebijakan yang tidak mendefinisikan checks", t => {
  const make = withFiles(t);
  expectInputError(/minimal satu entri checks/, "audit", make("no-checks.json", minimalPolicy()));
});

test("pewarisan siklik dan referensi induk yang salah ditolak", t => {
  const make = withFiles(t);
  expectInputError(/siklus a → b → a/, "validate",
    make("cycle.json", { ...minimalPolicy(), roles: { b: ["a"], a: ["b"] } }));
  expectInputError(/role yang tidak dikenal: hilang/, "validate",
    make("missing.json", { ...minimalPolicy(), roles: { staf: ["hilang"] } }));
});

test("rule atau check dengan aksi asing tidak menghasilkan keputusan", t => {
  const make = withFiles(t);
  const base = minimalPolicy();
  expectInputError(/dokumen\/hapus/, "validate", make("bad-action.json", {
    ...base, rules: [{ id: "salah", effect: "allow", roles: ["staf"], resource: "dokumen", actions: ["hapus"] }],
  }));
  expectInputError(/dokumen\/hapus/, "audit", make("bad-check.json", {
    ...base, checks: [{ id: "salah", expect: "deny", resource: "dokumen", actions: ["hapus"] }],
  }));
});

test("masukan role asing, relasi anonim, dan opsi ganda ditolak", () => {
  const args = ["explain", SAFE, "--resource", "dokumen", "--action", "baca"];
  expectInputError(/role yang tidak dikenal/, ...args, "--role", "hilang");
  expectInputError(/Skenario anonim/, ...args, "--owner");
  expectInputError(/Opsi --action berulang/, ...args, "--action", "ubah");
  expectInputError(/--limit harus/, "audit", SAFE, "--limit", "21");
});

test("syarat boolean dan kolom yang salah eja ditolak", t => {
  const make = withFiles(t);
  const rule = { id: "izin", effect: "allow", roles: ["staf"], resource: "dokumen", actions: ["baca"] };
  expectInputError(/owner harus true atau false/, "validate",
    make("wrong-type.json", { ...minimalPolicy(), rules: [{ ...rule, when: { owner: "true" } }] }));
  expectInputError(/kolom asing "sameunit"/, "validate",
    make("typo.json", { ...minimalPolicy(), rules: [{ ...rule, when: { sameunit: true } }] }));
});

test("properti JSON duplikat yang menggunakan escape Unicode ditolak", t => {
  const make = withFiles(t);
  const escapedKey = String.fromCharCode(92) + "u0076ersion";
  const duplicate = `{"version":1,"${escapedKey}":1,"roles":{},"resources":{"x":["y"]},"rules":[]}`;
  expectInputError(/Properti JSON berulang: "version"/, "validate", make("duplicate.json", duplicate));
});

test("batas masukan, JSON rusak, dan byte UTF-8 ilegal ditangani", t => {
  const make = withFiles(t);
  expectInputError(/256 KiB/, "validate", make("besar.json", Buffer.alloc(256 * 1024 + 1, 32)));
  expectInputError(/JSON tidak valid/, "validate", make("rusak.json", '{"version":1,'));
  expectInputError(/UTF-8 yang valid/, "validate", make("encoding.json", Buffer.from([0xff, 0xfe, 0x7b])));
});

test("diff menolak katalog aksi yang berubah agar ruang perbandingan jelas", t => {
  const make = withFiles(t);
  const altered = make("katalog.json", { ...SAMPLE, resources: { ...SAMPLE.resources, arsip: ["lihat"] } });
  expectInputError(/membutuhkan nama role dan pasangan resource\/aksi yang sama/, "diff", SAFE, altered);
});

test("keluaran terminal memuat temuan dan ID aturan yang menyebabkannya", () => {
  const result = cli("audit", LOOSE, "--limit", "1");
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stdout, /3 pelanggaran/);
  assert.match(result.stdout, /asisten \+ wali/);
  assert.match(result.stdout, /allow=asisten-baca-unit/);
});
