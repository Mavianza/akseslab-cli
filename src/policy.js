import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { TextDecoder } from "node:util";

const MAX_BYTES = 256 * 1024;
const MAX_ROLES = 10;
const MAX_RESOURCES = 12;
const MAX_CAPABILITIES = 48;
const MAX_RULES = 128;
const MAX_CHECKS = 48;
const NAME = /^[a-z][a-z0-9_-]{0,31}$/;
const RELATIONS = { owner: 1, sameUnit: 2 };

export class InputError extends Error {}

function object(value, label, allowed) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new InputError(`${label} harus berupa objek.`);
  }
  for (const key of Object.keys(value)) {
    if (allowed && !allowed.includes(key)) {
      throw new InputError(`${label} memuat kolom asing ${JSON.stringify(key)}.`);
    }
  }
  return value;
}

function array(value, label, max, min = 0) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    throw new InputError(`${label} harus berupa array dengan ${min}–${max} item.`);
  }
  return value;
}

function name(value, label) {
  if (typeof value !== "string" || !NAME.test(value)) {
    throw new InputError(`${label} harus berupa nama huruf kecil, angka, garis bawah, atau tanda hubung (1–32 karakter, diawali huruf).`);
  }
  return value;
}

function names(value, label, max, min = 0) {
  const list = array(value, label, max, min).map(item => name(item, label));
  if (new Set(list).size !== list.length) {
    throw new InputError(`${label} memuat nama duplikat.`);
  }
  return list;
}

function boolean(value, label) {
  if (typeof value !== "boolean") {
    throw new InputError(`${label} harus true atau false.`);
  }
  return value;
}

function effect(value, label) {
  if (value !== "allow" && value !== "deny") {
    throw new InputError(`${label} harus allow atau deny.`);
  }
  return value;
}

function entries(value, label, max, min = 0) {
  const result = Object.entries(object(value, label));
  if (result.length < min || result.length > max) {
    throw new InputError(`${label} harus memuat ${min}–${max} entri.`);
  }
  return result;
}

function roleMask(value, label, roleBits, min = 0) {
  let mask = 0;
  for (const role of names(value, label, MAX_ROLES, min)) {
    const bit = roleBits.get(role);
    if (bit === undefined) {
      throw new InputError(`${label} merujuk role yang tidak dikenal: ${role}.`);
    }
    mask |= bit;
  }
  return mask;
}

function compileRoles(input) {
  const parents = new Map(entries(input, "roles", MAX_ROLES).map(([role, inherited]) => [
    name(role, "Nama role"), names(inherited, `roles.${role}`, MAX_ROLES),
  ]));
  const roleNames = [...parents.keys()].sort();
  const roleBits = new Map(roleNames.map((role, index) => [role, 1 << index]));
  const closures = new Map();
  const visiting = [];

  function closure(role) {
    if (closures.has(role)) return closures.get(role);
    if (visiting.includes(role)) {
      const cycle = [...visiting.slice(visiting.indexOf(role)), role].join(" → ");
      throw new InputError(`Pewarisan role membentuk siklus ${cycle}.`);
    }
    visiting.push(role);
    let mask = roleBits.get(role);
    for (const parent of parents.get(role)) {
      if (!roleBits.has(parent)) {
        throw new InputError(`Role ${role} mewarisi role yang tidak dikenal: ${parent}.`);
      }
      mask |= closure(parent);
    }
    visiting.pop();
    closures.set(role, mask);
    return mask;
  }

  for (const role of roleNames) closure(role);
  const subjects = Array.from({ length: 1 << roleNames.length }, (_, mask) => {
    const assigned = roleNames.filter(role => (mask & roleBits.get(role)) !== 0);
    const effective = assigned.reduce((bits, role) => bits | closures.get(role), 0);
    return { mask, assigned, effective };
  });
  const orderedSubjects = [...subjects].sort((a, b) => a.assigned.length - b.assigned.length || a.mask - b.mask);
  return { roleNames, roleBits, subjects, orderedSubjects };
}

const capabilityKey = (resource, action) => `${resource}/${action}`;

function compileCapabilities(input) {
  const keys = [];
  for (const [resource, actions] of entries(input, "resources", MAX_RESOURCES, 1)) {
    name(resource, "Nama resource");
    for (const action of names(actions, `resources.${resource}`, MAX_CAPABILITIES, 1)) {
      keys.push(capabilityKey(resource, action));
    }
  }
  if (keys.length > MAX_CAPABILITIES) {
    throw new InputError(`Jumlah pasangan resource dan aksi maksimal ${MAX_CAPABILITIES}.`);
  }
  return new Map(keys.sort().map(key => {
    const [resource, action] = key.split("/");
    return [key, { key, resource, action, rules: [], checks: [] }];
  }));
}

function capabilityKeys(resource, actions, label, capabilities) {
  name(resource, `${label}.resource`);
  return names(actions, `${label}.actions`, MAX_CAPABILITIES, 1).map(action => {
    const key = capabilityKey(resource, action);
    if (!capabilities.has(key)) {
      throw new InputError(`${label} merujuk pasangan resource dan aksi yang tidak dikenal: ${key}.`);
    }
    return key;
  });
}

function condition(value, label) {
  const input = object(value, label, Object.keys(RELATIONS));
  let mask = 0;
  let expected = 0;
  for (const [key, flag] of Object.entries(input)) {
    const bit = RELATIONS[key];
    mask |= bit;
    if (boolean(flag, `${label}.${key}`)) expected |= bit;
  }
  return { mask, expected };
}

function selector(value, label, roleBits) {
  const input = object(value, label, ["allRoles", "noRoles", "anonymous"]);
  const all = roleMask(Object.hasOwn(input, "allRoles") ? input.allRoles : [], `${label}.allRoles`, roleBits);
  const none = roleMask(Object.hasOwn(input, "noRoles") ? input.noRoles : [], `${label}.noRoles`, roleBits);
  const anonymous = Object.hasOwn(input, "anonymous") ? boolean(input.anonymous, `${label}.anonymous`) : null;
  return { all, none, anonymous };
}

function records(input, collection, max, allowed) {
  const seen = new Set();
  return array(input, collection, max).map((raw, index) => {
    const item = object(raw, `${collection}[${index}]`, allowed);
    const id = name(item.id, `${collection}[${index}].id`);
    if (seen.has(id)) throw new InputError(`ID ${collection} berulang: ${id}.`);
    seen.add(id);
    return item;
  }).sort((a, b) => a.id < b.id ? -1 : Number(a.id > b.id));
}

export function compilePolicy(raw) {
  const input = object(raw, "Kebijakan", ["version", "roles", "resources", "rules", "checks"]);
  if (input.version !== 1) throw new InputError("version harus bernilai 1.");
  const roles = compileRoles(input.roles);
  const capabilities = compileCapabilities(input.resources);
  const rules = records(input.rules, "rules", MAX_RULES, ["id", "effect", "roles", "resource", "actions", "when"]);
  const rawChecks = Object.hasOwn(input, "checks") ? input.checks : [];
  const checks = records(rawChecks, "checks", MAX_CHECKS, ["id", "expect", "resource", "actions", "subject", "when"])
    .map((item, index) => {
      const label = `checks.${item.id}`;
      const check = {
        index, id: item.id, expect: effect(item.expect, `${label}.expect`),
        when: condition(Object.hasOwn(item, "when") ? item.when : {}, `${label}.when`),
        subject: selector(Object.hasOwn(item, "subject") ? item.subject : {}, `${label}.subject`, roles.roleBits),
      };
      for (const key of capabilityKeys(item.resource, item.actions, label, capabilities)) {
        capabilities.get(key).checks.push(check);
      }
      return check;
    });
  for (const item of rules) {
    const label = `rules.${item.id}`;
    const allRoles = Array.isArray(item.roles) && item.roles.length === 1 && item.roles[0] === "*";
    const rule = {
      id: item.id, effect: effect(item.effect, `${label}.effect`),
      roles: allRoles ? null : roleMask(item.roles, `${label}.roles`, roles.roleBits, 1),
      when: condition(Object.hasOwn(item, "when") ? item.when : {}, `${label}.when`),
    };
    for (const key of capabilityKeys(item.resource, item.actions, label, capabilities)) {
      capabilities.get(key).rules.push(rule);
    }
  }
  return { ...roles, capabilities, checks, ruleCount: rules.length };
}

export function request(model, { resource, action, roles, owner, sameUnit }) {
  const [key] = capabilityKeys(resource, [action], "Skenario", model.capabilities);
  const mask = roleMask(roles, "Skenario roles", model.roleBits);
  const bits = (boolean(owner, "owner") ? RELATIONS.owner : 0)
             | (boolean(sameUnit, "sameUnit") ? RELATIONS.sameUnit : 0);
  if (mask === 0 && bits !== 0) {
    throw new InputError("Skenario anonim hanya memiliki owner=false dan sameUnit=false.");
  }
  return { capability: model.capabilities.get(key), mask, bits };
}

export function scenario(model, capability, mask, bits) {
  const subject = model.subjects[mask];
  return {
    resource: capability.resource,
    action: capability.action,
    roles: subject.assigned,
    effectiveRoles: model.subjects[subject.effective].assigned,
    owner: Boolean(bits & RELATIONS.owner),
    sameUnit: Boolean(bits & RELATIONS.sameUnit),
  };
}

export function decide(model, capability, mask, bits) {
  const effective = model.subjects[mask].effective;
  const matched = { allow: [], deny: [] };
  for (const rule of capability.rules) {
    if ((rule.roles === null || (rule.roles & effective) !== 0)
        && (bits & rule.when.mask) === rule.when.expected) {
      matched[rule.effect].push(rule.id);
    }
  }
  if (matched.deny.length) return { decision: "deny", reason: "explicit-deny", matched };
  if (matched.allow.length) return { decision: "allow", reason: "matched-allow", matched };
  return { decision: "deny", reason: "default-deny", matched };
}

// Run after JSON.parse, so every string and delimiter is already well formed.
function rejectDuplicateKeys(text) {
  const stack = [];
  const colon = /[\t\r\n ]*:/y;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (char === "{") stack.push(new Set());
    else if (char === "[") stack.push(null);
    else if (char === "}" || char === "]") stack.pop();
    else if (char === '"') {
      const start = i++;
      while (text[i] !== '"') {
        if (text[i] === "\\") i += 1;
        i += 1;
      }
      const keys = stack.at(-1);
      colon.lastIndex = i + 1;
      if (keys && colon.test(text)) {
        const key = JSON.parse(text.slice(start, i + 1));
        if (keys.has(key)) throw new InputError(`Properti JSON berulang: ${JSON.stringify(key)}.`);
        keys.add(key);
      }
    }
  }
}

export function readPolicy(path) {
  let content;
  try {
    const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.size > MAX_BYTES) {
        throw new InputError("Kebijakan harus berupa berkas biasa dengan ukuran maksimal 256 KiB.");
      }
      const data = Buffer.alloc(MAX_BYTES + 1);
      let offset = 0;
      while (offset < data.length) {
        const count = readSync(fd, data, offset, data.length - offset, null);
        if (count === 0) break;
        offset += count;
      }
      if (offset > MAX_BYTES) throw new InputError("Berkas kebijakan melebihi 256 KiB.");
      content = new TextDecoder("utf-8", { fatal: true }).decode(data.subarray(0, offset));
    } finally {
      closeSync(fd);
    }
  } catch (error) {
    if (error instanceof InputError) throw error;
    if (error.code === "ERR_ENCODING_INVALID_ENCODED_DATA") {
      throw new InputError(`Berkas ${JSON.stringify(path)} harus berisi UTF-8 yang valid.`);
    }
    throw new InputError(`Berkas ${JSON.stringify(path)} tidak dapat dibaca (${error.code ?? "I/O"}).`);
  }
  let raw;
  try {
    raw = JSON.parse(content);
  } catch {
    throw new InputError(`JSON tidak valid pada berkas ${JSON.stringify(path)}.`);
  }
  rejectDuplicateKeys(content);
  return compilePolicy(raw);
}
