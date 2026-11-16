// perf/lib/results.test.js — issue #218 (FR6)
//
// resultsDir is pure: it must produce the exact directory layout and refuse a
// git SHA that could not have come from `git rev-parse`, so results are always
// tied to a real commit.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resultsDir } from './results.js';

// why: #218 FR6 fixes the layout as docs/perf/<date>/<scenario>-<sha7>-<time>Z
//      — assert the exact string for a fixed clock, not just that it "looks right"
test('exact path for a fixed date', () => {
  const d = new Date(Date.UTC(2026, 10, 16, 9, 5, 3));
  assert.equal(
    resultsDir(d, 'smoke', 'a0c0cda1b2c3'),
    'docs/perf/2026-11-16/smoke-a0c0cda-090503Z',
  );
});

// why: #218 a missing SHA would decouple results from the code under test
test('refuses missing SHA', () => {
  assert.throws(() => resultsDir(new Date(), 'smoke', ''), /GIT_SHA/);
  assert.throws(() => resultsDir(new Date(), 'smoke', undefined), /GIT_SHA/);
});

// why: #218 a SHA under 7 chars is not a usable commit abbreviation
test('refuses short SHA', () => {
  assert.throws(() => resultsDir(new Date(), 'smoke', 'abc123'), /GIT_SHA/);
});

// why: #218 uppercase hex is not `git rev-parse` output — refuse rather than
//      normalise, so odd inputs are visible (review-proofing A)
test('refuses uppercase SHA', () => {
  assert.throws(() => resultsDir(new Date(), 'smoke', 'A0C0CDA1B2C3'), /GIT_SHA/);
});

// why: #218 non-hex chars are not a commit SHA
test('refuses non-hex SHA', () => {
  assert.throws(() => resultsDir(new Date(), 'smoke', 'g0c0cda1b2c3'), /GIT_SHA/);
});

// why: #218 a scenario name is a path component — refuse traversal-shaped ones
test('refuses traversal-shaped scenario', () => {
  assert.throws(() => resultsDir(new Date(), '../x', 'a0c0cda1'), /scenario/);
});

// why: #218 the function must stay pure — the caller (Makefile/workflow) owns
//      mkdir; a silent write here would bypass the RESULTS_DIR contract
test('accepts 40-char and 7-char SHAs at the bounds', () => {
  assert.equal(
    resultsDir(new Date(Date.UTC(2026, 0, 2, 3, 4, 5)), 'load', 'abcdef1'),
    'docs/perf/2026-01-02/load-abcdef1-030405Z',
  );
  assert.ok(
    resultsDir(new Date(Date.UTC(2026, 0, 2, 3, 4, 5)), 'load', 'a'.repeat(40)).endsWith('-030405Z'),
  );
});
