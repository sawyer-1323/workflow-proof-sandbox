'use strict';

// Golden test: every row of spec/arith-spec.md, encoded in
// test/golden/expected.json. Protected baseline (see golden-guard).

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const arith = require('../src/arith.js');

const golden = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'golden', 'expected.json'), 'utf8'),
);

test('golden file has the twelve specified cases', () => {
  assert.equal(golden.cases.length, 12);
});

for (const c of golden.cases) {
  test(`golden case ${c.id}: ${c.op}(${c.a}, ${c.b}) = ${c.expected}`, () => {
    assert.equal(typeof arith[c.op], 'function');
    assert.equal(arith[c.op](c.a, c.b), c.expected);
  });
}
