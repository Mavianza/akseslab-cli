import { decide, InputError, scenario } from "./policy.js";

const RELATION_CASES = 4;

function* contexts(model) {
  for (const subject of model.orderedSubjects) {
    const count = subject.mask === 0 ? 1 : RELATION_CASES;
    for (let bits = 0; bits < count; bits += 1) yield { mask: subject.mask, bits };
  }
}

function applies(check, mask, bits) {
  const { subject, when } = check;
  return (subject.anonymous === null || subject.anonymous === (mask === 0))
    && (mask & subject.all) === subject.all
    && (mask & subject.none) === 0
    && (bits & when.mask) === when.expected;
}

export function audit(model, limit) {
  if (!model.checks.length) throw new InputError("Audit membutuhkan minimal satu entri checks.");
  const checks = model.checks.map(({ id, expect }) => ({ id, expect, tested: 0, failed: 0, examples: [] }));
  const capabilities = [...model.capabilities.values()].filter(item => item.checks.length);
  let evaluated = 0;
  let assertions = 0;
  let violations = 0;
  for (const { mask, bits } of contexts(model)) {
    for (const capability of capabilities) {
      let outcome;
      for (const check of capability.checks) {
        if (!applies(check, mask, bits)) continue;
        if (outcome === undefined) {
          outcome = decide(model, capability, mask, bits);
          evaluated += 1;
        }
        const row = checks[check.index];
        row.tested += 1;
        assertions += 1;
        if (outcome.decision === check.expect) continue;
        row.failed += 1;
        violations += 1;
        if (row.examples.length < limit) {
          row.examples.push({ ...scenario(model, capability, mask, bits), ...outcome });
        }
      }
    }
  }
  let emptyChecks = 0;
  for (const row of checks) {
    row.status = row.tested === 0 ? "empty" : row.failed > 0 ? "fail" : "pass";
    if (row.status === "empty") emptyChecks += 1;
  }
  const possible = (1 + RELATION_CASES * (model.subjects.length - 1)) * model.capabilities.size;
  return {
    schemaVersion: 1, mode: "audit", passed: violations === 0 && emptyChecks === 0,
    possible, evaluated, assertions, violations, emptyChecks, checks,
  };
}

export function diff(before, after, limit) {
  if (before.roleNames.join(",") !== after.roleNames.join(",")
      || [...before.capabilities.keys()].join(",") !== [...after.capabilities.keys()].join(",")) {
    throw new InputError("Diff membutuhkan nama role dan pasangan resource/aksi yang sama pada kedua kebijakan.");
  }

  const gained = { count: 0, examples: [] };
  const lost = { count: 0, examples: [] };
  let evaluated = 0;
  for (const { mask, bits } of contexts(before)) {
    for (const [key, previous] of before.capabilities) {
      const current = after.capabilities.get(key);
      const left = decide(before, previous, mask, bits);
      const right = decide(after, current, mask, bits);
      evaluated += 1;
      if (left.decision === right.decision) continue;
      const bucket = right.decision === "allow" ? gained : lost;
      bucket.count += 1;
      if (bucket.examples.length < limit) {
        const { effectiveRoles, ...input } = scenario(before, previous, mask, bits);
        bucket.examples.push({
          ...input,
          before: { effectiveRoles, ...left },
          after: { effectiveRoles: after.subjects[after.subjects[mask].effective].assigned, ...right },
        });
      }
    }
  }
  return {
    schemaVersion: 1, mode: "diff", passed: gained.count === 0,
    evaluated, unchanged: evaluated - gained.count - lost.count, gained, lost,
  };
}
