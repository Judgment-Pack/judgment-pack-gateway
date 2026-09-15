// Writes the flatted fixtures the n8n checker's tests read, with the flatted
// n8n itself stores execution data with -- run inside the pinned n8n image,
// so the bytes are the library's and not an imitation of it:
//
//   docker run --rm -v "$PWD/plugins/smoke/testing:/work" --entrypoint node \
//     docker.n8n.io/n8nio/n8n:2.38.7@sha256:a8c95f75c6fdf65f5f2b7a7b354744eaa1c62bb911b5c00af6499c3f38e4cd32 \
//     /work/make_flatted_fixtures.cjs \
//     /usr/local/lib/node_modules/n8n/node_modules/.pnpm/flatted@3.4.2/node_modules/flatted /work/fixtures
//
// fixtures/n8n-execution.json (written by test_n8n_check.py's
// write_execution_fixture) is the execution as the engine must have
// answered; this writes it as n8n stores it. It also writes the decoder's
// cases -- shared objects, a string that recurs, a key and a value that read
// as numbers beside a number, keys a JavaScript object orders first -- and
// what they decode to, cycles, and a long chain.
const fs = require('node:fs');
const path = require('node:path');

const [flattedDir, fixtures] = process.argv.slice(2);
const flatted = require(flattedDir);
const { version } = require(path.join(flattedDir, 'package.json'));
if (version !== '3.4.2') {
	throw new Error(`flatted ${version}, not the 3.4.2 the pinned n8n image stores with`);
}

const execution = JSON.parse(fs.readFileSync(path.join(fixtures, 'n8n-execution.json'), 'utf8'));
fs.writeFileSync(path.join(fixtures, 'n8n-execution.flatted.json'), flatted.stringify(execution));

// the same object test_n8n_check.py's flatted_cases builds
const shared = { subject: 'acme', 7: 'seven' };
const list = ['7', 7, shared, null, true, false, '', 'é中😀'];
const cases = {
	seven: 7,
	7: '7',
	sevenAgain: '7',
	shared,
	list,
	nested: { again: shared, list, 10: 10, 2: 'two', '02': 'not an index' },
	empty: {},
	none: [],
};
fs.writeFileSync(path.join(fixtures, 'flatted-cases.flatted.json'), flatted.stringify(cases));
fs.writeFileSync(path.join(fixtures, 'flatted-cases.json'), JSON.stringify(cases));

// cycles, which flatted writes and its parse gives back as cycles: an object
// that holds itself, an array that holds itself, and two objects that hold
// each other -- the same object test_n8n_check.py's flatted_cycles builds
const cyclic = { name: 'root' };
cyclic.self = cyclic;
const ring = ['ring'];
ring.push(ring);
cyclic.ring = ring;
const a = { name: 'a' };
const b = { name: 'b', a };
a.b = b;
cyclic.pair = a;
fs.writeFileSync(path.join(fixtures, 'flatted-cycles.flatted.json'), flatted.stringify(cyclic));

// a chain 600 objects long, which the library writes and reads: a decoder
// that recurses through it would run out of stack -- the same object
// test_n8n_check.py's flatted_chain builds
const chain = { depth: 0 };
let link = chain;
for (let depth = 1; depth < 600; depth++) {
	link.next = { depth };
	link = link.next;
}
fs.writeFileSync(path.join(fixtures, 'flatted-chain.flatted.json'), flatted.stringify(chain));
console.log(`flatted ${version}: wrote the execution and the decoder's cases`);
