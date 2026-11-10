'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const arith = require('../src/arith.js');

test('add and subtract', () => {
  assert.equal(arith.add(2, 3), 5);
  assert.equal(arith.subtract(3, 5), -2);
});

test('multiply', () => {
  assert.equal(arith.multiply(-4, 6), -24);
});

test('divideFloor rounds toward negative infinity', () => {
  assert.equal(arith.divideFloor(9, 4), 2);
  assert.equal(arith.divideFloor(-9, 4), -3);
  assert.throws(() => arith.divideFloor(1, 0), RangeError);
});

test('roundHalfEven rejects a non-positive denominator', () => {
  assert.throws(() => arith.roundHalfEven(1, 0), RangeError);
  assert.throws(() => arith.roundHalfEven(1, -2), RangeError);
});

test('inputs must be safe integers', () => {
  assert.throws(() => arith.add(1.5, 1), TypeError);
  assert.throws(() => arith.add(Number.MAX_SAFE_INTEGER, 1), RangeError);
});
