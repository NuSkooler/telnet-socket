'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const TelnetSocket = require('../lib/telnet_socket');

//  a TelnetSocket over a stand-in for a net.Socket; |bytes| arrive as one
//  chunk, and every command it emits is returned in order
const feed = bytes => {
    const socket = new EventEmitter();
    socket.write = () => true;
    const telnet = new TelnetSocket(socket);
    const events = [];
    ['SB', 'WILL', 'command error'].forEach(name =>
        telnet.on(name, (command, err) => events.push({ name, command, err }))
    );
    const data = [];
    telnet.on('data', chunk => data.push(chunk));
    socket.emit('data', Buffer.from(bytes));
    //  readable data is delivered on a later tick
    const text = () =>
        new Promise(resolve => setImmediate(() => resolve(Buffer.concat(data).toString('latin1'))));
    return { events, text };
};

const IAC = 255;
const SB = 250;
const SE = 240;
const NAWS = 31;
const TTYPE = 24;
const WILL = 251;

const naws = payload => [IAC, SB, NAWS, ...payload, IAC, SE];

test('NAWS: the 4 byte payload', () => {
    const { events } = feed(naws([0x00, 0x50, 0x00, 0x19]));
    assert.equal(events.length, 1);
    assert.equal(events[0].name, 'SB');
    assert.deepEqual(events[0].command.optionData, { width: 80, height: 25 });
});

test('NAWS: sent without WILL NAWS first is still read', () => {
    //  NetRunner never sends WILL NAWS
    const { events } = feed([IAC, WILL, TTYPE, ...naws([0x00, 0x84, 0x00, 0x32])]);
    assert.deepEqual(
        events.map(e => e.name),
        ['WILL', 'SB']
    );
    assert.deepEqual(events[1].command.optionData, { width: 132, height: 50 });
});

test("NAWS: NetRunner's payload padded with a NUL each side", () => {
    const { events } = feed(naws([0x00, 0x00, 0x50, 0x00, 0x19, 0x00]));
    assert.equal(events.length, 1);
    assert.equal(events[0].name, 'SB');
    assert.deepEqual(events[0].command.optionData, { width: 80, height: 25 });
});

test('NAWS: an escaped 255 (IAC IAC) in the payload', () => {
    const { events } = feed(naws([0x00, IAC, IAC, 0x00, 0x19]));
    assert.deepEqual(events[0].command.optionData, { width: 255, height: 25 });
});

test('NAWS: any other length is a command error, not an SB', () => {
    [
        [0x00, 0x50, 0x00, 0x19, 0x00], //  5 bytes
        [0x01, 0x00, 0x50, 0x00, 0x19, 0x00], //  6 bytes, no leading NUL
        [0x00, 0x00, 0x50, 0x00, 0x19, 0x01], //  6 bytes, no trailing NUL
        [0x00, 0x00, 0x00, 0x50, 0x00, 0x19, 0x00], //  7 bytes
    ].forEach(payload => {
        const { events } = feed(naws(payload));
        assert.equal(events.length, 1, `one event for ${payload}`);
        assert.equal(events[0].name, 'command error', `${payload}`);
        assert.equal(events[0].command.name, 'SB');
        assert.equal(events[0].command.option, NAWS);
        assert.equal(events[0].command.optionData, undefined);
        assert(events[0].err instanceof Error);
    });
});

test('a command error leaves the data after it alone', async () => {
    const { events, text } = feed([
        ...naws([0x00, 0x50, 0x00, 0x19, 0x00]),
        0x41,
        ...naws([0x00, 0x50, 0x00, 0x19]),
        0x42,
    ]);
    assert.deepEqual(
        events.map(e => e.name),
        ['command error', 'SB']
    );
    assert.equal(await text(), 'AB');
});

test('NAWS: a payload under 4 bytes does not hold back the input after it', async () => {
    const { events, text } = feed([...naws([0x00, 0x50]), 0x41]);
    assert.deepEqual(
        events.map(e => e.name),
        ['command error']
    );
    assert.equal(await text(), 'A');
});

test('NAWS: an escaped 255 followed by 240 (SE) is not the end', async () => {
    //  width 0xFFF0: FF is escaped, F0 is the low byte
    const { events, text } = feed([...naws([IAC, IAC, SE, 0x00, 0x19]), 0x41]);
    assert.deepEqual(
        events.map(e => e.name),
        ['SB']
    );
    assert.deepEqual(events[0].command.optionData, { width: 0xfff0, height: 25 });
    assert.equal(await text(), 'A');
});

test('NAWS: split across chunks', () => {
    const socket = new EventEmitter();
    socket.write = () => true;
    const telnet = new TelnetSocket(socket);
    const got = [];
    telnet.on('SB', command => got.push(command.optionData));
    const bytes = naws([0x00, 0x50, 0x00, 0x19]);
    bytes.forEach(b => socket.emit('data', Buffer.from([b])));
    assert.deepEqual(got, [{ width: 80, height: 25 }]);
});
