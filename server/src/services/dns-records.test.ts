import assert from 'node:assert/strict';
import test from 'node:test';
import { encodeName, parseResponse, readName } from './dns-records.js';

function u16(value: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value, 0);
  return buffer;
}

function u32(value: number): Buffer {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value, 0);
  return buffer;
}

// Builds a minimal, well-formed DNS response message: header + one question
// + zero or more answer records, so parseResponse's happy-path and
// error-path behavior can be exercised directly with crafted fixtures.
function buildMessage(options: {
  id?: number;
  rcode?: number;
  name?: string;
  qtype?: number;
  answers?: Array<{ type: number; klass?: number; ttl?: number; rdata: Buffer }>;
}): Buffer {
  const { id = 0x1234, rcode = 0, name = 'example.com', qtype = 43, answers = [] } = options;

  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x8000 | rcode, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);

  const question = Buffer.concat([encodeName(name), u16(qtype), u16(1)]);

  const answerBuffers = answers.map((answer) =>
    Buffer.concat([
      encodeName(name),
      u16(answer.type),
      u16(answer.klass ?? 1),
      u32(answer.ttl ?? 300),
      u16(answer.rdata.length),
      answer.rdata,
    ])
  );

  return Buffer.concat([header, question, ...answerBuffers]);
}

test('parseResponse returns matching answer records', () => {
  const rdata = Buffer.from([0x01, 0x02, 0x03, 0x04]);
  const message = buildMessage({ answers: [{ type: 43, rdata }] });
  const records = parseResponse(message, 0x1234, 43);
  assert.equal(records.length, 1);
  assert.equal(records[0].type, 43);
  assert.deepEqual(records[0].data, rdata);
});

test('parseResponse ignores answers of a different type/class', () => {
  const message = buildMessage({
    answers: [
      { type: 5, rdata: Buffer.from([0xaa]) },
      { type: 43, klass: 3, rdata: Buffer.from([0xbb]) },
    ],
  });
  const records = parseResponse(message, 0x1234, 43);
  assert.equal(records.length, 0);
});

test('parseResponse rejects a mismatched transaction id', () => {
  const message = buildMessage({ id: 0x1234 });
  assert.throws(() => parseResponse(message, 0x9999, 43), /Invalid DNS response/);
});

test('parseResponse rejects a message shorter than the DNS header', () => {
  assert.throws(() => parseResponse(Buffer.alloc(4), 0, 43), /Invalid DNS response/);
});

test('parseResponse surfaces NXDOMAIN (rcode 3) as ENOTFOUND', () => {
  const message = buildMessage({ rcode: 3 });
  assert.throws(
    () => parseResponse(message, 0x1234, 43),
    (error: NodeJS.ErrnoException) => error.code === 'ENOTFOUND'
  );
});

test('parseResponse surfaces other non-zero rcodes with a distinct error code', () => {
  const message = buildMessage({ rcode: 2 });
  assert.throws(
    () => parseResponse(message, 0x1234, 43),
    (error: NodeJS.ErrnoException) => error.code === 'EDNSRCODE2'
  );
});

test('parseResponse rejects a record whose rdlength overruns the buffer', () => {
  const rdata = Buffer.from([0x01, 0x02, 0x03, 0x04]);
  const message = buildMessage({ answers: [{ type: 43, rdata }] });
  // Lie about the answer count so the loop tries to read a second record
  // that was never appended, walking past the end of the buffer.
  message.writeUInt16BE(2, 6);
  assert.throws(() => parseResponse(message, 0x1234, 43), /Truncated DNS/);
});

test('parseResponse rejects a message truncated mid fixed-size answer fields', () => {
  const message = buildMessage({ answers: [{ type: 43, rdata: Buffer.alloc(0) }] });
  // Chop off the last few bytes so the fixed 10-byte type/class/ttl/rdlength
  // block for the answer cannot be fully read.
  const truncated = message.subarray(0, message.length - 8);
  assert.throws(() => parseResponse(truncated, 0x1234, 43), /Truncated DNS response/);
});

test('readName follows a compression pointer back to an earlier name', () => {
  const first = encodeName('example.com');
  const pointer = Buffer.from([0xc0, 0x00]); // pointer to offset 0
  const message = Buffer.concat([first, pointer]);
  const result = readName(message, first.length);
  assert.equal(result.name, 'example.com');
  assert.equal(result.offset, first.length + 2);
});

test('readName rejects a name that runs past the end of the buffer', () => {
  const message = Buffer.from([5, 97, 98, 99]); // claims a 5-byte label but only 3 bytes follow
  assert.throws(() => readName(message, 0), /Truncated DNS label/);
});

test('readName rejects a name whose length byte is entirely missing', () => {
  assert.throws(() => readName(Buffer.alloc(0), 0), /Truncated DNS name/);
});

test('readName bounds a self-referencing compression pointer loop instead of hanging', () => {
  // Points at itself: following it can never terminate via a null label, so
  // the depth guard must trip.
  const message = Buffer.from([0xc0, 0x00]);
  assert.throws(() => readName(message, 0), /DNS name compression loop/);
});
