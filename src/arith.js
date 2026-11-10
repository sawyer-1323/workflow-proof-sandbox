'use strict';

// Integer arithmetic helpers for a synthetic test project.
// Every function accepts and returns safe integers only.

function requireSafeInteger(value, name) {
  if (!Number.isSafeInteger(value)) {
    throw new TypeError(`${name} must be a safe integer`);
  }
}

function checkResult(value) {
  if (!Number.isSafeInteger(value)) {
    throw new RangeError('result is outside the safe integer range');
  }
  return value;
}

function add(a, b) {
  requireSafeInteger(a, 'a');
  requireSafeInteger(b, 'b');
  return checkResult(a + b);
}

function subtract(a, b) {
  requireSafeInteger(a, 'a');
  requireSafeInteger(b, 'b');
  return checkResult(a - b);
}

function multiply(a, b) {
  requireSafeInteger(a, 'a');
  requireSafeInteger(b, 'b');
  return checkResult(a * b);
}

// Floor division: rounds toward negative infinity.
function divideFloor(a, b) {
  requireSafeInteger(a, 'a');
  requireSafeInteger(b, 'b');
  if (b === 0) {
    throw new RangeError('division by zero');
  }
  return checkResult(Math.floor(a / b));
}

// Rounds numerator / denominator to the nearest integer, ties to even.
// The denominator must be positive.
function roundHalfEven(numerator, denominator) {
  requireSafeInteger(numerator, 'numerator');
  requireSafeInteger(denominator, 'denominator');
  if (denominator <= 0) {
    throw new RangeError('denominator must be positive');
  }
  const quotient = Math.floor(numerator / denominator);
  const remainder = numerator - quotient * denominator;
  const twice = 2 * remainder;
  if (twice < denominator) {
    return checkResult(quotient);
  }
  if (twice > denominator) {
    return checkResult(quotient + 1);
  }
  return checkResult(quotient % 2 === 0 ? quotient : quotient + 1);
}

module.exports = { add, subtract, multiply, divideFloor, roundHalfEven };
