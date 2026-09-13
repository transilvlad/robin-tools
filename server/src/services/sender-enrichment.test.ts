import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createRequestDeadline,
  remainingRequestTime,
  sweepExpired,
  type CacheEntry,
} from './sender-enrichment.js';

test('MTA-STS redirects share one absolute request deadline', () => {
  const deadline = createRequestDeadline(1_000, 10_000);

  assert.equal(deadline, 11_000);
  assert.equal(remainingRequestTime(deadline, 10_600), 400);
  assert.equal(remainingRequestTime(deadline, 11_100), 0);
});

test('sweepExpired removes only entries past their expiry, regardless of last read', () => {
  const now = 10_000;
  const map = new Map<string, CacheEntry<string>>([
    ['stale-ip', { value: 'never looked up again', expires: now - 1 }],
    ['fresh-ip', { value: 'still valid', expires: now + 1 }],
    ['exactly-at-now', { value: 'boundary', expires: now }],
  ]);

  sweepExpired(map, now);

  // Strictly-less-than-now matches cacheGet()'s own eviction rule: an entry
  // expiring exactly "now" is still considered valid, only "stale-ip" (whose
  // expiry is in the past) is swept.
  assert.deepEqual([...map.keys()], ['fresh-ip', 'exactly-at-now']);
});
