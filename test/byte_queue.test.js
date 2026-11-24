'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const ByteQueue = require('../lib/byte_queue');

//  a queue holding |chunks|, each pushed separately
const queueOf = (...chunks) => {
    const q = new ByteQueue();
    chunks.forEach(c => q.push(Buffer.from(c)));
    return q;
};

const contents = q => [...q.toBuffer()];

describe('construction', () => {
    test('a new queue is empty', () => {
        const q = new ByteQueue();
        assert.equal(q.length, 0);
        assert.deepEqual(contents(q), []);
        assert.equal(q.indexOf(Buffer.from([1])), -1);
    });

    test('an initial buffer is adopted', () => {
        const q = new ByteQueue(Buffer.from([1, 2, 3]));
        assert.equal(q.length, 3);
        assert.deepEqual(contents(q), [1, 2, 3]);
    });

    test('a fresh queue resets: nothing of the old one carries over', () => {
        let q = queueOf([1, 2], [3]);
        q = new ByteQueue();
        q.push(Buffer.from([9]));
        assert.deepEqual(contents(q), [9]);
    });
});

describe('push() and length', () => {
    test('chunks are appended in order and length is their total', () => {
        const q = new ByteQueue();
        assert.equal(q.push(Buffer.from([1, 2])), 2);
        assert.equal(q.push(Buffer.from([3]), Buffer.from([4, 5])), 5);
        assert.equal(q.push(Buffer.alloc(0)), 5);
        assert.equal(q.length, 5);
        assert.deepEqual(contents(q), [1, 2, 3, 4, 5]);
    });

    test('a non-buffer is refused and nothing is pushed', () => {
        const q = queueOf([1]);
        assert.throws(() => q.push(Buffer.from([2]), 'x'), TypeError);
        assert.deepEqual(contents(q), [1]);
    });

    test('the pushed buffer is copied, not kept', () => {
        const q = new ByteQueue();
        const b = Buffer.from([1, 2]);
        q.push(b);
        b[0] = 9;
        assert.deepEqual(contents(q), [1, 2]);
    });

    test('grows past its initial capacity a byte at a time', () => {
        const q = new ByteQueue();
        for (let i = 0; i < 70000; i++) {
            q.push(Buffer.from([i & 0xff]));
        }
        assert.equal(q.length, 70000);
        assert.equal(q.get(0), 0);
        assert.equal(q.get(69999), 69999 & 0xff);
    });

    test('reuses the space freed at the front', () => {
        const q = new ByteQueue();
        q.push(Buffer.alloc(200, 1));
        q.splice(0, 150);
        q.push(Buffer.alloc(150, 2)); //  fits once the front is reclaimed
        assert.equal(q.length, 200);
        assert.equal(q.get(0), 1);
        assert.equal(q.get(49), 1);
        assert.equal(q.get(50), 2);
        assert.equal(q.get(199), 2);
    });
});

describe('get()', () => {
    test('reads across chunk boundaries', () => {
        const q = queueOf([1, 2], [3], [4, 5, 6]);
        assert.deepEqual(
            [0, 1, 2, 3, 4, 5].map(i => q.get(i)),
            [1, 2, 3, 4, 5, 6]
        );
    });

    test('out of range throws oob', () => {
        const q = queueOf([1, 2]);
        assert.throws(() => q.get(2), /oob/);
        assert.throws(() => q.get(-1), /oob/);
        assert.throws(() => new ByteQueue().get(0), /oob/);
    });

    test('indexes from the current front after a splice', () => {
        const q = queueOf([1, 2, 3, 4]);
        q.splice(0, 2);
        assert.equal(q.get(0), 3);
        assert.throws(() => q.get(2), /oob/);
    });
});

describe('indexOf()', () => {
    test('finds a byte', () => {
        assert.equal(queueOf([1, 2, 3]).indexOf(Buffer.from([3])), 2);
    });

    test('finds a needle split over chunks', () => {
        const q = queueOf([1, 255], [240, 2]);
        assert.equal(q.indexOf(Buffer.from([255, 240])), 1);
        assert.equal(queueOf([1, 2], [3], [4, 5]).indexOf(Buffer.from([2, 3, 4])), 1);
    });

    test('from an offset', () => {
        const q = queueOf([255, 240], [0, 255, 240]);
        assert.equal(q.indexOf(Buffer.from([255, 240])), 0);
        assert.equal(q.indexOf(Buffer.from([255, 240]), 1), 3);
        assert.equal(q.indexOf(Buffer.from([255, 240]), 3), 3);
        assert.equal(q.indexOf(Buffer.from([255, 240]), 4), -1);
    });

    test('after a partial match', () => {
        assert.equal(queueOf([255, 255], [255, 240]).indexOf(Buffer.from([255, 240])), 2);
    });

    test('not found', () => {
        assert.equal(queueOf([1, 2], [3]).indexOf(Buffer.from([4])), -1);
        //  a match must end inside the queue
        assert.equal(queueOf([1, 255]).indexOf(Buffer.from([255, 240])), -1);
    });

    test('never matches bytes already spliced off', () => {
        const q = queueOf([255, 240, 1, 2]);
        q.splice(0, 2);
        assert.equal(q.indexOf(Buffer.from([255, 240])), -1);
        q.push(Buffer.from([255]));
        assert.equal(q.indexOf(Buffer.from([255])), 2);
    });

    test('a string needle is UTF-8', () => {
        assert.equal(queueOf([0x61], [0xc3, 0xa9]).indexOf('\xe9'), 1);
    });

    test('an empty needle is found at 0, even in an empty queue', () => {
        assert.equal(new ByteQueue().indexOf(Buffer.alloc(0)), 0);
        assert.equal(queueOf([1]).indexOf('', 5), 0);
    });

    test('an empty queue finds nothing, whatever the offset', () => {
        assert.equal(new ByteQueue().indexOf(Buffer.from([1]), 3), -1);
    });

    test('an offset outside the queue throws oob', () => {
        const q = queueOf([1, 2, 3]);
        assert.throws(() => q.indexOf(Buffer.from([1]), 3), /oob/);
        assert.throws(() => q.indexOf(Buffer.from([1]), -1), /oob/);
    });

    test('a needle that is not a Buffer or string throws', () => {
        assert.throws(() => queueOf([1]).indexOf([1]), /Invalid type for a search string/);
    });
});

describe('splice()', () => {
    test('from the front across chunks', () => {
        const q = queueOf([1, 2], [3, 4], [5]);
        const removed = q.splice(0, 3);
        assert(removed instanceof ByteQueue);
        assert.deepEqual(contents(removed), [1, 2, 3]);
        assert.deepEqual(contents(q), [4, 5]);
        assert.equal(q.length, 2);
    });

    test('from the middle across chunks', () => {
        const q = queueOf([1, 2], [3, 4], [5, 6]);
        assert.deepEqual(contents(q.splice(1, 4)), [2, 3, 4, 5]);
        assert.deepEqual(contents(q), [1, 6]);
    });

    test('at the end', () => {
        const q = queueOf([1, 2, 3]);
        assert.deepEqual(contents(q.splice(2, 5)), [3]);
        assert.deepEqual(contents(q), [1, 2]);
    });

    test('the whole thing, with and without a count', () => {
        let q = queueOf([1], [2, 3]);
        assert.deepEqual(contents(q.splice(0)), [1, 2, 3]);
        assert.equal(q.length, 0);

        q = queueOf([1], [2, 3]);
        assert.deepEqual(contents(q.splice(0, 3)), [1, 2, 3]);
        assert.equal(q.length, 0);
    });

    test('a count past the end is clamped', () => {
        const q = queueOf([1, 2, 3]);
        assert.deepEqual(contents(q.splice(1, 99)), [2, 3]);
        assert.deepEqual(contents(q), [1]);
    });

    test('nothing', () => {
        const q = queueOf([1, 2]);
        for (const removed of [q.splice(0, 0), q.splice(1, 0), q.splice(2), q.splice(0, -1)]) {
            assert.equal(removed.length, 0);
            assert.deepEqual(contents(removed), []);
        }
        assert.deepEqual(contents(new ByteQueue().splice(0)), []);
        assert.deepEqual(contents(q), [1, 2]);
    });

    test('the start is clamped into the queue', () => {
        const q = queueOf([1, 2]);
        assert.deepEqual(contents(q.splice(-5, 1)), [1]);
        assert.deepEqual(contents(q.splice(9)), []);
        assert.deepEqual(contents(q.splice()), [2]);
    });

    test('the removed bytes are a copy', () => {
        const q = queueOf([1, 2, 3, 4]);
        const removed = q.splice(0, 2);
        q.push(Buffer.from([7, 8, 9])); //  may reuse the freed space
        assert.deepEqual(contents(removed), [1, 2]);
        assert.deepEqual(contents(q), [3, 4, 7, 8, 9]);
    });

    test('the removed queue works as a queue', () => {
        const removed = queueOf([1, 2, 3]).splice(0, 2);
        assert.equal(removed.length, 2);
        assert.equal(removed.get(1), 2);
        assert.equal(removed.indexOf(Buffer.from([2])), 1);
        removed.push(Buffer.from([4]));
        assert.deepEqual(contents(removed), [1, 2, 4]);
    });

    test('an emptied queue gives up a large buffer and still works', () => {
        const q = new ByteQueue();
        q.push(Buffer.alloc(100000, 1));
        q.splice(0);
        assert.equal(q.storage.length, 0);
        q.push(Buffer.from([2]));
        assert.deepEqual(contents(q), [2]);
    });
});

describe('toBuffer(), slice() and toString()', () => {
    test('toBuffer() is a fresh copy each time', () => {
        const q = queueOf([1, 2], [3]);
        const a = q.toBuffer();
        assert(Buffer.isBuffer(a));
        assert.deepEqual([...a], [1, 2, 3]);
        a[0] = 9;
        assert.deepEqual(contents(q), [1, 2, 3]);
    });

    test('slice() takes a start and end, clamping the end', () => {
        const q = queueOf([1, 2], [3, 4]);
        assert.deepEqual([...q.slice(1, 3)], [2, 3]);
        assert.deepEqual([...q.slice(2)], [3, 4]);
        assert.deepEqual([...q.slice(1, 99)], [2, 3, 4]);
        assert.deepEqual([...q.slice()], [1, 2, 3, 4]);
    });

    test('toString() decodes all or part', () => {
        const q = queueOf([0x61, 0x62], [0x63]);
        assert.equal(q.toString(), 'abc');
        assert.equal(q.toString('latin1', 1), 'bc');
        assert.equal(q.toString('hex', 0, 2), '6162');
    });
});
