'use strict';

//
//  Characterization tests: these pin what TelnetSocket emits today, quirks
//  included, so the internals can change underneath without a behaviour
//  change. A test marked "quirk" pins behaviour that is odd but current.
//

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');

const TelnetSocket = require('../lib/telnet_socket');
const { CommandNames } = require('../lib/telnet_spec');

const IAC = 255;
const DONT = 254;
const DO = 253;
const WONT = 252;
const WILL = 251;
const SB = 250;
const AYT = 246;
const NOP = 241;
const SE = 240;

const ECHO = 1;
const TTYPE = 24;
const NEW_ENVIRON = 39;
const MSSP = 70;

//  TTYPE / NEW-ENVIRON subcommands
const IS = 0;
const SEND = 1;
const INFO = 2;
const VAR = 0;
const VALUE = 1;
const ESC = 2;
const USERVAR = 3;

const EVENT_NAMES = [...new Set(Object.values(CommandNames)), 'unknown command', 'command error', 'error'];

const bytes = s => [...Buffer.from(s, 'latin1')];

const makeSocket = () => {
    const socket = new EventEmitter();
    socket.writes = [];
    socket.write = (data, cb) => {
        socket.writes.push(Buffer.from(data));
        if ('function' === typeof cb) {
            cb(null);
        }
        return true;
    };
    socket.corked = 0;
    socket.cork = () => socket.corked++;
    socket.uncork = () => socket.corked--;
    return socket;
};

//  A TelnetSocket over a stand-in socket. Each of |chunks| arrives as one
//  'data' event; every command event is recorded in order. |raw| is
//  replaced by its bytes so it can be compared.
const feedChunks = chunks => {
    const socket = makeSocket();
    const telnet = new TelnetSocket(socket);
    const events = [];
    EVENT_NAMES.forEach(name =>
        telnet.on(name, (command, err) => {
            if ('error' === name) {
                events.push({ name, message: command.message });
                return;
            }
            const e = { name, command: { ...command } };
            if (command.optionData && command.optionData.raw) {
                e.command.optionData = { raw: [...command.optionData.raw.toBuffer()] };
            }
            if (command.parsed) {
                e.command.parsed = command.parsed.message;
            }
            if (err) {
                e.err = err.message;
            }
            events.push(e);
        })
    );
    const data = [];
    telnet.on('data', chunk => data.push(chunk));
    chunks.forEach(c => socket.emit('data', Buffer.from(c)));
    //  readable data is delivered on a later tick
    const output = () => new Promise(resolve => setImmediate(() => resolve([...Buffer.concat(data)])));
    return { telnet, socket, events, output };
};

const feed = b => feedChunks([b]);

//  every byte in its own chunk
const feedBytewise = b => feedChunks(b.map(x => [x]));

//  |b| gives the same events and data in one chunk and byte by byte
const sameSplit = async (b, expectedEvents, expectedData) => {
    for (const run of [feed(b), feedBytewise(b)]) {
        assert.deepEqual(run.events, expectedEvents);
        assert.deepEqual(await run.output(), expectedData);
    }
};

const sb = (option, optionName, optionData) => {
    const command = { code: SB, option, name: 'SB', optionName };
    if (optionData) {
        command.optionData = optionData;
    }
    return { name: 'SB', command };
};

const sbError = (option, optionName, message) => ({
    name: 'command error',
    command: { code: SB, option, name: 'SB', optionName, parsed: message },
    err: message,
});

const ttypeIs = value => [IAC, SB, TTYPE, IS, ...value, IAC, SE];
const environ = (cmd, payload) => [IAC, SB, NEW_ENVIRON, cmd, ...payload, IAC, SE];

describe('negotiation commands', () => {
    test('DO, DONT, WILL and WONT', async () => {
        await sameSplit(
            [IAC, DO, ECHO, IAC, DONT, TTYPE, IAC, WILL, NEW_ENVIRON, IAC, WONT, 31],
            [
                { name: 'DO', command: { code: DO, option: ECHO, name: 'DO', optionName: 'ECHO' } },
                { name: 'DONT', command: { code: DONT, option: TTYPE, name: 'DONT', optionName: 'TTYPE' } },
                {
                    name: 'WILL',
                    command: { code: WILL, option: NEW_ENVIRON, name: 'WILL', optionName: 'NEW_ENVIRON' },
                },
                { name: 'WONT', command: { code: WONT, option: 31, name: 'WONT', optionName: 'NAWS' } },
            ],
            []
        );
    });

    test('an option with no name', async () => {
        await sameSplit(
            [IAC, DO, 200],
            [{ name: 'DO', command: { code: DO, option: 200, name: 'DO', optionName: 'unknown option' } }],
            []
        );
    });

    test('a 2 byte command such as AYT, NOP or SE', async () => {
        await sameSplit(
            [IAC, AYT, IAC, NOP, IAC, SE],
            [
                {
                    name: 'AYT',
                    command: { code: AYT, option: undefined, name: 'AYT', optionName: 'unknown option' },
                },
                {
                    name: 'NOP',
                    command: { code: NOP, option: undefined, name: 'NOP', optionName: 'unknown option' },
                },
                { name: 'SE', command: { code: SE, option: undefined, name: 'SE', optionName: 'unknown option' } },
            ],
            []
        );
    });

    test('a command code that is not one', async () => {
        await sameSplit(
            [IAC, 0x10, 0x41],
            [
                {
                    name: 'unknown command',
                    command: { code: 0x10, option: undefined, name: 'unknown command', optionName: 'unknown option' },
                },
            ],
            [0x41]
        );
    });
});

describe('the data stream', () => {
    test('plain data passes through', async () => {
        await sameSplit(bytes('hello'), [], bytes('hello'));
    });

    test('IAC IAC is a literal 0xFF', async () => {
        await sameSplit([0x41, IAC, IAC, 0x42, IAC, IAC, IAC, IAC], [], [0x41, 0xff, 0x42, 0xff, 0xff]);
    });

    test('data before, between and after commands', async () => {
        await sameSplit(
            [...bytes('ab'), IAC, WILL, ECHO, ...bytes('cd'), IAC, AYT, ...bytes('ef')],
            [
                { name: 'WILL', command: { code: WILL, option: ECHO, name: 'WILL', optionName: 'ECHO' } },
                {
                    name: 'AYT',
                    command: { code: AYT, option: undefined, name: 'AYT', optionName: 'unknown option' },
                },
            ],
            bytes('abcdef')
        );
    });

    test('a lone IAC at the end of a chunk is held for the next', async () => {
        const run = feedChunks([[0x41, IAC], [WILL], [ECHO, 0x42]]);
        assert.deepEqual(
            run.events.map(e => e.name),
            ['WILL']
        );
        assert.deepEqual(await run.output(), [0x41, 0x42]);
    });

    test('passthrough skips all parsing', async () => {
        const socket = makeSocket();
        const telnet = new TelnetSocket(socket);
        telnet.passthrough = true;
        const seen = [];
        telnet.on('WILL', () => seen.push('WILL'));
        const data = [];
        telnet.on('data', chunk => data.push(chunk));
        socket.emit('data', Buffer.from([IAC, WILL, ECHO, IAC, IAC]));
        await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(seen, []);
        assert.deepEqual([...Buffer.concat(data)], [IAC, WILL, ECHO, IAC, IAC]);
    });
});

describe('TTYPE', () => {
    test('IS', async () => {
        await sameSplit(ttypeIs(bytes('xterm-256color')), [sb(TTYPE, 'TTYPE', { ttype: 'xterm-256color' })], []);
    });

    test("IS with NetRunner's trailing NUL", async () => {
        await sameSplit(
            ttypeIs(bytes('ANSI-256COLOR-RGB\0')),
            [sb(TTYPE, 'TTYPE', { ttype: 'ANSI-256COLOR-RGB' })],
            []
        );
    });

    test('IS: a NUL in the middle ends the value', async () => {
        await sameSplit(ttypeIs(bytes('ANSI\0junk')), [sb(TTYPE, 'TTYPE', { ttype: 'ANSI' })], []);
    });

    test('IS: bytes over 0x7F are decoded as ascii', async () => {
        await sameSplit(
            ttypeIs([0x41, 0xc1, 0x80]),
            [sb(TTYPE, 'TTYPE', { ttype: Buffer.from([0x41, 0xc1, 0x80]).toString('ascii') })],
            []
        );
    });

    test('IS: a 256 byte value is accepted', async () => {
        const value = 'A'.repeat(256);
        await sameSplit(ttypeIs(bytes(value)), [sb(TTYPE, 'TTYPE', { ttype: value })], []);
    });

    test('IS: a 257 byte value is a command error', async () => {
        await sameSplit(
            [...ttypeIs(bytes('A'.repeat(257))), 0x41],
            [sbError(TTYPE, 'TTYPE', 'TTYPE value exceeds maximum length')],
            [0x41]
        );
    });

    test('IS: the cap counts bytes before the NUL is cut', async () => {
        await sameSplit(
            ttypeIs(bytes('ANSI\0' + 'x'.repeat(252))),
            [sbError(TTYPE, 'TTYPE', 'TTYPE value exceeds maximum length')],
            []
        );
    });

    test('IS: an escaped 0xFF (IAC IAC) in the value is a command error', async () => {
        await sameSplit(
            [...ttypeIs([0x41, IAC, IAC, 0x42]), 0x43],
            [sbError(TTYPE, 'TTYPE', 'Invalid TTYPE option structure')],
            [0x43]
        );
    });

    test('IS: data after it', async () => {
        await sameSplit(
            [...bytes('a'), ...ttypeIs(bytes('VT100')), ...bytes('b')],
            [sb(TTYPE, 'TTYPE', { ttype: 'VT100' })],
            bytes('ab')
        );
    });

    test('IS waits for its IAC SE', async () => {
        const run = feedChunks([[IAC, SB, TTYPE, IS, 0x41, 0x42], [0x43, IAC], [SE, 0x44]]);
        assert.deepEqual(run.events, [sb(TTYPE, 'TTYPE', { ttype: 'ABC' })]);
        assert.deepEqual(await run.output(), [0x44]);
    });

    test('quirk: an empty IS waits for a later IAC SE and takes it all', async () => {
        //  IAC SB TTYPE IS IAC SE is 6 bytes and the IS path needs 7; the
        //  search for IAC SE starts past the first one, so everything up to
        //  the next IAC SE is consumed and the value reads as empty
        const run = feedChunks([[IAC, SB, TTYPE, IS, IAC, SE], [0x41, 0x42, IAC, SE, 0x43]]);
        assert.deepEqual(run.events, [sb(TTYPE, 'TTYPE', { ttype: '' })]);
        assert.deepEqual(await run.output(), [0x43]);
    });

    test('quirk: an empty IS followed by IAC SE in one chunk is an empty value', async () => {
        await sameSplit([IAC, SB, TTYPE, IS, IAC, SE, IAC, SE], [sb(TTYPE, 'TTYPE', { ttype: '' })], []);
    });

    test('SEND', async () => {
        await sameSplit([IAC, SB, TTYPE, SEND, IAC, SE, 0x41], [sb(TTYPE, 'TTYPE', { send: true })], [0x41]);
    });

    test('a malformed SEND is a command error and its 6 bytes are consumed', async () => {
        await sameSplit(
            [IAC, SB, TTYPE, SEND, 0x41, 0x42, 0x43],
            [sbError(TTYPE, 'TTYPE', 'Invalid TTYPE SEND structure')],
            [0x43]
        );
    });

    test('a subcommand other than IS or SEND is a command error', async () => {
        await sameSplit(
            [IAC, SB, TTYPE, INFO, 0x41, IAC, SE, 0x42],
            [sbError(TTYPE, 'TTYPE', 'Invalid TTYPE option structure')],
            [0x42]
        );
    });

    test('quirk: an IAC other than IAC SE after the value is a command error', async () => {
        //  the value ends at the first IAC; the byte after it must be SE
        await sameSplit(
            [IAC, SB, TTYPE, IS, 0x41, IAC, NOP, 0x42, IAC, SE],
            [sbError(TTYPE, 'TTYPE', 'Invalid TTYPE option structure')],
            []
        );
    });
});

describe('NEW-ENVIRON', () => {
    const env = (cmd, vars, uservars) => ({
        command: cmd,
        commandName: cmd === IS ? 'IS' : 'INFO',
        vars,
        uservars,
    });

    test('IS with VAR and USERVAR values', async () => {
        await sameSplit(
            environ(IS, [
                VAR,
                ...bytes('USER'),
                VALUE,
                ...bytes('bryan'),
                USERVAR,
                ...bytes('COLUMNS'),
                VALUE,
                ...bytes('80'),
                VAR,
                ...bytes('TERM'),
                VALUE,
                ...bytes('xterm'),
            ]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [{ USER: 'bryan' }, { TERM: 'xterm' }], [{ COLUMNS: '80' }]))],
            []
        );
    });

    test('INFO', async () => {
        await sameSplit(
            environ(INFO, [USERVAR, ...bytes('LINES'), VALUE, ...bytes('50')]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(INFO, [], [{ LINES: '50' }]))],
            []
        );
    });

    test('an empty list', async () => {
        await sameSplit(environ(IS, []), [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [], []))], []);
    });

    test('empty values and no values are null', async () => {
        await sameSplit(
            environ(IS, [VAR, ...bytes('A'), VALUE, VAR, ...bytes('B'), VALUE, USERVAR, ...bytes('C')]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [{ A: null }, { B: null }], [{ C: null }]))],
            []
        );
    });

    test('names are case sensitive', async () => {
        await sameSplit(
            environ(IS, [VAR, ...bytes('term'), VALUE, ...bytes('a'), VAR, ...bytes('TERM'), VALUE, ...bytes('b')]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [{ term: 'a' }, { TERM: 'b' }], []))],
            []
        );
    });

    test('ESC escapes the next byte in names and values', async () => {
        await sameSplit(
            environ(IS, [
                VAR,
                ...bytes('A'),
                ESC,
                VAR,
                ...bytes('B'),
                VALUE,
                ...bytes('x'),
                ESC,
                VALUE,
                ...bytes('y'),
                ESC,
                ESC,
                USERVAR,
                ESC,
                USERVAR,
                ...bytes('U'),
                VALUE,
                ESC,
                USERVAR,
            ]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [{ 'A\x00B': 'x\x01y\x02' }], [{ '\x03U': '\x03' }]))],
            []
        );
    });

    test('quirk: an unescaped VAR or USERVAR inside a name is part of the name', async () => {
        await sameSplit(
            environ(IS, [VAR, ...bytes('A'), VAR, ...bytes('B'), USERVAR, ...bytes('C')]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [{ 'A\x00B\x03C': null }], []))],
            []
        );
    });

    test('quirk: a value with no name has the name ""; at the end it is dropped', async () => {
        await sameSplit(
            environ(IS, [VAR, VALUE, ...bytes('x'), VAR, ...bytes('B'), VALUE, VAR, VALUE, ...bytes('y')]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [{ '': 'x' }, { B: null }], []))],
            []
        );
    });

    test('quirk: a USERVAR name ending in ESC is filed under vars', async () => {
        await sameSplit(
            environ(IS, [USERVAR, ...bytes('A'), ESC]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [{ A: null }], []))],
            []
        );
    });

    test('a value ending in ESC keeps its field', async () => {
        await sameSplit(
            environ(IS, [USERVAR, ...bytes('A'), VALUE, ...bytes('v'), ESC, VAR, ...bytes('B'), VALUE, ESC]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [], [{ A: 'v\x00B\x01' }]))],
            []
        );
        await sameSplit(
            environ(IS, [VAR, ...bytes('A'), VALUE, ...bytes('v'), ESC]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [{ A: 'v' }], []))],
            []
        );
    });

    test('a list not starting with VAR or USERVAR is a command error', async () => {
        await sameSplit(
            [...environ(IS, [VALUE, ...bytes('A')]), 0x41],
            [sbError(NEW_ENVIRON, 'NEW_ENVIRON', 'Invalid NEW-ENVIRON structure')],
            [0x41]
        );
    });

    test('a command other than IS or INFO is a command error', async () => {
        await sameSplit(
            environ(SEND, [VAR, ...bytes('A')]),
            [sbError(NEW_ENVIRON, 'NEW_ENVIRON', 'Invalid NEW-ENVIRON structure')],
            []
        );
    });

    test('an escaped 0xFF (IAC IAC) is a command error', async () => {
        await sameSplit(
            environ(IS, [VAR, ...bytes('A'), VALUE, IAC, IAC]),
            [sbError(NEW_ENVIRON, 'NEW_ENVIRON', 'Invalid NEW-ENVIRON structure')],
            []
        );
    });

    test('waits for its IAC SE', async () => {
        const run = feedChunks([[IAC, SB, NEW_ENVIRON, IS, VAR, 0x41], [VALUE, 0x42, IAC], [SE, 0x43]]);
        assert.deepEqual(run.events, [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [{ A: 'B' }], []))]);
        assert.deepEqual(await run.output(), [0x43]);
    });

    test('names and values are decoded as ascii', async () => {
        const name = Buffer.from([0xc1]).toString('ascii');
        const value = Buffer.from([0xe9]).toString('ascii');
        await sameSplit(
            environ(IS, [VAR, 0xc1, VALUE, 0xe9]),
            [sb(NEW_ENVIRON, 'NEW_ENVIRON', env(IS, [{ [name]: value }], []))],
            []
        );
    });
});

describe('an SB for an option without a parser', () => {
    test('optionData.raw is the whole subnegotiation', async () => {
        const sub = [IAC, SB, MSSP, 1, ...bytes('NAME'), 2, ...bytes('BBS'), IAC, SE];
        const run = feed([...sub, 0x41]);
        assert.deepEqual(run.events, [sb(MSSP, 'MSSP', { raw: sub })]);
        assert.deepEqual(await run.output(), [0x41]);
    });

    test('optionData.raw has length, get() and toBuffer()', () => {
        const socket = makeSocket();
        const telnet = new TelnetSocket(socket);
        let raw;
        telnet.on('SB', command => (raw = command.optionData.raw));
        socket.emit('data', Buffer.from([IAC, SB, 200, 0x41, 0x42, IAC, SE]));
        assert.equal(raw.length, 7);
        assert.equal(raw.get(0), IAC);
        assert.equal(raw.get(4), 0x42);
        assert.throws(() => raw.get(7));
        const first = raw.toBuffer();
        assert(Buffer.isBuffer(first));
        assert.deepEqual([...first], [IAC, SB, 200, 0x41, 0x42, IAC, SE]);
        //  each call is a fresh copy
        first[0] = 0;
        assert.equal(raw.toBuffer()[0], IAC);
        assert.equal(raw.toString('latin1'), Buffer.from([IAC, SB, 200, 0x41, 0x42, IAC, SE]).toString('latin1'));
    });

    test('with no IAC SE yet, it waits: the payload is not passed on as data', async () => {
        const run = feedChunks([[IAC, SB, MSSP, 0x41, 0x42], [IAC, SE, 0x43]]);
        assert.deepEqual(run.events, [sb(MSSP, 'MSSP', { raw: [IAC, SB, MSSP, 0x41, 0x42, IAC, SE] })]);
        assert.deepEqual(await run.output(), [0x43]);
    });

    test('IAC SB OPTION as the last 3 buffered bytes waits (it used to throw)', async () => {
        const socket = makeSocket();
        const telnet = new TelnetSocket(socket);
        const got = [];
        const data = [];
        telnet.on('SB', command => got.push([...command.optionData.raw.toBuffer()]));
        telnet.on('data', chunk => data.push(...chunk));
        assert.doesNotThrow(() => socket.emit('data', Buffer.from([0x41, IAC, SB, MSSP])));
        assert.doesNotThrow(() => socket.emit('data', Buffer.from([IAC])));
        assert.deepEqual(got, []);
        socket.emit('data', Buffer.from([0x42, IAC, SE, 0x43]));
        assert.deepEqual(got, [[IAC, SB, MSSP, IAC, 0x42, IAC, SE]]);
        await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(data, [0x41, 0x43]);
    });

    test('an unknown SB sent a byte at a time never throws', () => {
        const socket = makeSocket();
        const telnet = new TelnetSocket(socket);
        const got = [];
        telnet.on('SB', command => got.push([...command.optionData.raw.toBuffer()]));
        const sub = [IAC, SB, MSSP, 1, 0x41, 2, 0x42, IAC, SE];
        sub.forEach(b => assert.doesNotThrow(() => socket.emit('data', Buffer.from([b]))));
        assert.deepEqual(got, [sub]);
    });
});

describe('split across chunks', () => {
    //  each of these gives the same result fed byte by byte (sameSplit);
    //  this is a mixed stream of all of them
    test('a mixed stream, byte by byte', async () => {
        const stream = [
            ...bytes('x'),
            IAC,
            DO,
            ECHO,
            IAC,
            IAC,
            ...ttypeIs(bytes('ANSI-256COLOR-RGB\0')),
            IAC,
            SB,
            TTYPE,
            SEND,
            IAC,
            SE,
            ...environ(IS, [VAR, ...bytes('TERM'), VALUE, ...bytes('ansi')]),
            IAC,
            SB,
            31,
            0,
            80,
            0,
            25,
            IAC,
            SE,
            IAC,
            AYT,
            ...bytes('y'),
        ];
        const whole = feed(stream);
        const split = feedBytewise(stream);
        assert.deepEqual(
            whole.events.map(e => e.name),
            ['DO', 'SB', 'SB', 'SB', 'SB', 'AYT']
        );
        assert.deepEqual(split.events, whole.events);
        assert.deepEqual(await split.output(), [0x78, 0xff, 0x79]);
        assert.deepEqual(await whole.output(), [0x78, 0xff, 0x79]);
    });
});

describe('buffer overflow', () => {
    test('a single chunk over 64 KB is an error and is dropped', async () => {
        const run = feed(Buffer.alloc(65537, 0x41));
        assert.deepEqual(run.events, [{ name: 'error', message: 'Telnet buffer overflow: stream reset' }]);
        assert.deepEqual(await run.output(), []);
    });

    test('64 KB exactly is not', async () => {
        const run = feed(Buffer.alloc(65536, 0x41));
        assert.deepEqual(run.events, []);
        assert.equal((await run.output()).length, 65536);
    });

    test('an unterminated SB that grows past 64 KB resets the stream', async () => {
        const chunks = [[IAC, SB, TTYPE, IS], Buffer.alloc(65532, 0x41), [0x41]];
        const run = feedChunks(chunks);
        assert.deepEqual(run.events, [{ name: 'error', message: 'Telnet buffer overflow: stream reset' }]);
        //  the stream carries on afterwards
        run.socket.emit('data', Buffer.from([IAC, WILL, ECHO, 0x42]));
        assert.deepEqual(
            run.events.map(e => e.name),
            ['error', 'WILL']
        );
        assert.deepEqual(await run.output(), [0x42]);
    });
});

describe('_write()', () => {
    const written = socket => [...Buffer.concat(socket.writes)];

    test('IAC bytes are doubled', async () => {
        const socket = makeSocket();
        const telnet = new TelnetSocket(socket);
        await new Promise(resolve => telnet.write(Buffer.from([IAC, 0x41, IAC, IAC, 0x42, IAC]), resolve));
        assert.deepEqual(written(socket), [IAC, IAC, 0x41, IAC, IAC, IAC, IAC, 0x42, IAC, IAC]);
        assert.equal(socket.corked, 0);
    });

    test('data without IAC is written as is', async () => {
        const socket = makeSocket();
        const telnet = new TelnetSocket(socket);
        await new Promise(resolve => telnet.write(Buffer.from('plain'), resolve));
        assert.deepEqual(socket.writes, [Buffer.from('plain')]);
    });

    test('a string is escaped byte for byte (binary), not by code point', () => {
        const socket = makeSocket();
        const telnet = new TelnetSocket(socket);
        let called = false;
        telnet._write('a\xffb', null, () => (called = true));
        assert(called);
        assert.deepEqual(written(socket), [0x61, IAC, IAC, 0x62]);
    });

    test('no escaping in passthrough or with escapeIACs off', async () => {
        for (const setup of [t => (t.passthrough = true), t => (t.escapeIACs = false)]) {
            const socket = makeSocket();
            const telnet = new TelnetSocket(socket);
            setup(telnet);
            await new Promise(resolve => telnet.write(Buffer.from([IAC, 0x41]), resolve));
            assert.deepEqual(written(socket), [IAC, 0x41]);
        }
    });
});

describe('sending commands', () => {
    test('do/dont/will/wont and sb.send', () => {
        const socket = makeSocket();
        const telnet = new TelnetSocket(socket);
        telnet.do.ttype();
        telnet.will.echo();
        telnet.sb.send.ttype();
        telnet.sb.send.new_environ(['TERM']);
        assert.deepEqual(socket.writes.map(b => [...b]), [
            [IAC, DO, TTYPE],
            [IAC, WILL, ECHO],
            [IAC, SB, TTYPE, SEND, IAC, SE],
            [IAC, SB, NEW_ENVIRON, SEND, VAR, ...bytes('TERM'), USERVAR, IAC, SE],
        ]);
    });

    test('sb.send.mssp and sb.send.gmcp', () => {
        const socket = makeSocket();
        const telnet = new TelnetSocket(socket);
        telnet.sb.send.mssp({ NAME: 'BBS', PLAYERS: '3' });
        telnet.sb.send.gmcp('Core.Hello', '{}');
        telnet.sb.send.gmcp('Core.Ping');
        telnet.dont.naws();
        telnet.wont.ttype();
        assert.deepEqual(socket.writes.map(b => [...b]), [
            [IAC, SB, MSSP, 1, ...bytes('NAME'), 2, ...bytes('BBS'), 1, ...bytes('PLAYERS'), 2, ...bytes('3'), IAC, SE],
            [IAC, SB, 201, ...bytes('Core.Hello {}'), IAC, SE],
            [IAC, SB, 201, ...bytes('Core.Ping'), IAC, SE],
            [IAC, DONT, 31],
            [IAC, WONT, TTYPE],
        ]);
    });

    test('commandBuffer takes a number or an object with .code', () => {
        assert.deepEqual([...TelnetSocket.commandBuffer(DO, { code: ECHO })], [IAC, DO, ECHO]);
        assert.deepEqual([...TelnetSocket.commandBuffer(SB, TTYPE, [SEND, IAC, SE])], [IAC, SB, TTYPE, SEND, IAC, SE]);
    });
});

describe('the wrapped socket', () => {
    test('rawSocket is the socket', () => {
        const socket = makeSocket();
        assert.equal(new TelnetSocket(socket).rawSocket, socket);
    });

    test('its events are re-emitted', () => {
        const socket = makeSocket();
        const telnet = new TelnetSocket(socket);
        const seen = [];
        ['close', 'connect', 'drain', 'end', 'error', 'lookup', 'ready', 'timeout'].forEach(name =>
            telnet.on(name, (...args) => seen.push([name, ...args]))
        );
        const err = new Error('boom');
        socket.emit('close', false);
        socket.emit('connect');
        socket.emit('drain');
        socket.emit('end');
        socket.emit('error', err);
        socket.emit('lookup', null, '127.0.0.1', 4, 'localhost');
        socket.emit('ready');
        socket.emit('timeout');
        assert.deepEqual(seen, [
            ['close', false],
            ['connect'],
            ['drain'],
            ['end'],
            ['error', err],
            ['lookup', null, '127.0.0.1', 4, 'localhost'],
            ['ready'],
            ['timeout'],
        ]);
    });

    test('ending the TelnetSocket ends the socket', async () => {
        const socket = makeSocket();
        let ended = false;
        socket.end = cb => {
            ended = true;
            cb();
        };
        const telnet = new TelnetSocket(socket);
        await new Promise(resolve => telnet.end(resolve));
        assert(ended);
    });
});
