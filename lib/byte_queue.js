'use strict';

//
//  A queue of bytes that arrive in chunks, with random access, search and
//  removal. It replaces the |buffers| module and keeps the part of its API
//  that telnet-socket uses, and that an unknown SB's optionData.raw exposes
//  to consumers: length, push(), get(), indexOf(), splice(), toBuffer(),
//  slice() and toString(). Out of range get() and indexOf() offsets throw
//  Error('oob') as |buffers| did.
//
//  The bytes live in one buffer, between |head| and |tail|, that grows by
//  doubling: get() is O(1), indexOf() is a native search, and taking bytes
//  off the front only moves |head|. A byte-at-a-time stream costs one copy
//  per byte in and one per command out.
//

const MIN_CAPACITY = 256;
const MAX_RETAINED_CAPACITY = 65536; //  an empty queue keeps up to this much

const EMPTY = Buffer.alloc(0);

class ByteQueue {
    //  |initial|, if given, is adopted rather than copied
    constructor(initial) {
        this.storage = initial || EMPTY;
        this.head = 0;
        this.tail = this.storage.length;
    }

    get length() {
        return this.tail - this.head;
    }

    push(...buffers) {
        buffers.forEach(buf => {
            if (!Buffer.isBuffer(buf)) {
                throw new TypeError('Tried to push a non-buffer');
            }
        });

        buffers.forEach(buf => {
            this._reserve(buf.length);
            buf.copy(this.storage, this.tail);
            this.tail += buf.length;
        });
        return this.length;
    }

    get(i) {
        if (i < 0 || i >= this.length) {
            throw new Error('oob');
        }
        return this.storage[this.head + i];
    }

    //  the index of |needle| (a Buffer, or a string as UTF-8) at or after
    //  |offset|, or -1
    indexOf(needle, offset) {
        if ('string' === typeof needle) {
            needle = Buffer.from(needle);
        } else if (!Buffer.isBuffer(needle)) {
            throw new Error('Invalid type for a search string');
        }

        if (!needle.length) {
            return 0;
        }

        if (!this.length) {
            return -1;
        }

        if (offset) {
            if (offset < 0 || offset >= this.length) {
                throw new Error('oob');
            }
        } else {
            offset = 0;
        }

        return this._bytes().indexOf(needle, offset);
    }

    //  remove |count| bytes (default: all) from |start|, returning them as a
    //  new ByteQueue
    splice(start, count) {
        const length = this.length;
        start = Math.min(Math.max(start || 0, 0), length);
        if (undefined === count || count > length - start) {
            count = length - start;
        }
        if (!(count > 0)) {
            return new ByteQueue();
        }

        const from = this.head + start;
        const removed = Buffer.from(this.storage.subarray(from, from + count));

        if (0 === start) {
            this.head += count;
        } else {
            this.storage.copyWithin(from, from + count, this.tail);
            this.tail -= count;
        }

        if (this.head === this.tail) {
            this.head = this.tail = 0;
            if (this.storage.length > MAX_RETAINED_CAPACITY) {
                this.storage = EMPTY;
            }
        }

        return new ByteQueue(removed);
    }

    //  a copy of bytes |start| (default 0) up to |end| (default: all)
    slice(start, end) {
        const length = this.length;
        if (undefined === end || end > length) {
            end = length;
        }
        if (undefined === start) {
            start = 0;
        }
        return Buffer.from(this._bytes().subarray(start, end));
    }

    //  a copy of every byte
    toBuffer() {
        return this.slice();
    }

    toString(encoding, start, end) {
        return this.slice(start, end).toString(encoding);
    }

    _bytes() {
        return this.storage.subarray(this.head, this.tail);
    }

    //  make room for |n| more bytes at |tail|
    _reserve(n) {
        if (this.tail + n <= this.storage.length) {
            return;
        }

        const length = this.length;
        if (length + n <= this.storage.length) {
            this.storage.copyWithin(0, this.head, this.tail);
        } else {
            let capacity = Math.max(this.storage.length, MIN_CAPACITY);
            while (capacity < length + n) {
                capacity *= 2;
            }
            const storage = Buffer.allocUnsafe(capacity);
            this.storage.copy(storage, 0, this.head, this.tail);
            this.storage = storage;
        }
        this.head = 0;
        this.tail = length;
    }
}

module.exports = ByteQueue;
