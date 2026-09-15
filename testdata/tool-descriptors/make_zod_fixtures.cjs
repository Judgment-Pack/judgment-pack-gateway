// Writes zod.json: what zod-to-json-schema emits for the arguments of a
// tool -- the MCP TypeScript SDK converts a tool's zod shape with it,
// strictUnions on, and sends the result -- with whether schema grammar 1
// accepts it, and if not, where it refuses (docs/design/tool-descriptors.md).
//
// Each expectation is written by hand. Run with the versions named in
// GENERATOR, which the file records:
//
//   npm install --prefix /tmp/z zod@3.25.76 zod-to-json-schema@3.24.6
//   NODE_PATH=/tmp/z/node_modules node make_zod_fixtures.cjs
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { z } = require('zod');
const { zodToJsonSchema } = require('zod-to-json-schema');

const GENERATOR = 'zod 3.25.76, zod-to-json-schema 3.24.6, { strictUnions: true }';
// A package's version from its package.json, found where require finds it.
function versionOf(name) {
  for (const dir of require.resolve.paths(name)) {
    const file = path.join(dir, name, 'package.json');
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8')).version;
  }
  throw new Error(`${name} is not installed`);
}
for (const [name, version] of [['zod', '3.25.76'], ['zod-to-json-schema', '3.24.6']]) {
  if (versionOf(name) !== version) throw new Error(`${name} is ${versionOf(name)}, not ${version}`);
}

const address = z.object({ city: z.string() });

// [name, shape, the refusal written by hand: null, or [code, pointer]]
const FIXTURES = [
  ['search_tickets', z.object({ query: z.string().describe('Search text'), limit: z.number().int().min(1).max(100).default(10) }), null],
  ['filters', z.object({ status: z.enum(['open', 'closed']), closed: z.boolean().optional(), tags: z.array(z.string()).min(1).max(5) }), null],
  ['nullable', z.object({ owner: z.string().nullable(), note: z.union([z.string(), z.null()]) }), null],
  ['record', z.object({ counts: z.record(z.number()) }), null],
  ['bounds', z.object({ ratio: z.number().positive().lt(1), name: z.string().min(1).max(80), step: z.number().multipleOf(0.25) }), null],
  ['literal', z.object({ kind: z.literal('ticket') }), null],
  ['nested', z.object({ address: z.object({ city: z.string(), zip: z.string().optional() }) }), null],
  ['anything', z.object({ anything: z.any(), unknown: z.unknown() }), null],
  ['discriminated', z.object({
    target: z.discriminatedUnion('type', [z.object({ type: z.literal('a'), a: z.string() }), z.object({ type: z.literal('b'), b: z.number() })]),
  }), null],
  ['email', z.object({ email: z.string().email() }), ['keyword', '/properties/email/format']],
  ['regex', z.object({ code: z.string().regex(/^[A-Z]{3}$/) }), ['keyword', '/properties/code/pattern']],
  ['uuid', z.object({ id: z.string().uuid() }), ['keyword', '/properties/id/format']],
  ['datetime', z.object({ since: z.string().datetime() }), ['keyword', '/properties/since/format']],
  // A tuple is the array form of items.
  ['tuple', z.object({ pair: z.tuple([z.string(), z.number()]) }), ['value', '/properties/pair/items']],
  // A shape used twice is written once and referred to after.
  ['repeated', z.object({ home: address, work: address }), ['keyword', '/properties/work/$ref']],
];

const out = {
  about: [
    'Input schemas as zod-to-json-schema emits them for a tool\'s arguments, each written as the MCP',
    'TypeScript SDK sends it, compact. Written by make_zod_fixtures.cjs, whose expectations are written by hand.',
  ],
  generator: GENERATOR,
  fixtures: FIXTURES.map(([name, shape, refusal]) => ({
    name,
    text: JSON.stringify(zodToJsonSchema(shape, { strictUnions: true })),
    refusal: refusal && { code: refusal[0], pointer: refusal[1] },
  })),
};
// ASCII, as vectors.json is: every code unit past printable ASCII escaped.
const json = JSON.stringify(out, null, 1);
let ascii = '';
for (let i = 0; i < json.length; i++) {
  const unit = json.charCodeAt(i);
  ascii += unit < 0x7f ? json[i] : '\\u' + unit.toString(16).padStart(4, '0');
}
fs.writeFileSync('zod.json', ascii + '\n');
