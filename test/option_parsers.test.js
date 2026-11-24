'use strict';

//  Direct tests of the TTYPE IS and NEW-ENVIRON parsers, which take a
//  complete IAC SB ... IAC SE subnegotiation. How TelnetSocket waits for one
//  to arrive is in telnet_socket.test.js.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { parseTTYPE, parseNewEnviron } = require('../lib/option_parsers');

const IAC = 255;
const SB = 250;
const NOP = 241;
const SE = 240;
const TTYPE = 24;
const NEW_ENVIRON = 39;

const IS = 0;
const SEND = 1;
const INFO = 2;
const VAR = 0;
const VALUE = 1;
const ESC = 2;
const USERVAR = 3;

const bytes = s => [...Buffer.from(s, 'latin1')];

const errorMessage = result => {
    assert(result instanceof Error, `expected an Error, got ${JSON.stringify(result)}`);
    return result.message;
};

describe('parseTTYPE()', () => {
    const ttype = value => Buffer.from([IAC, SB, TTYPE, IS, ...value, IAC, SE]);

    test('a value', () => {
        assert.deepEqual(parseTTYPE(ttype(bytes('xterm'))), { ttype: 'xterm' });
    });

    test('an empty value', () => {
        assert.deepEqual(parseTTYPE(ttype([])), { ttype: '' });
    });

    test('a NUL ends the value', () => {
        assert.deepEqual(parseTTYPE(ttype(bytes('ANSI-256COLOR-RGB\0'))), { ttype: 'ANSI-256COLOR-RGB' });
        assert.deepEqual(parseTTYPE(ttype(bytes('\0ANSI'))), { ttype: '' });
    });

    test('the value is decoded as ascii', () => {
        assert.deepEqual(parseTTYPE(ttype([0xc1, 0x41])), {
            ttype: Buffer.from([0xc1, 0x41]).toString('ascii'),
        });
    });

    test('255 and 256 byte values are accepted', () => {
        for (const n of [255, 256]) {
            assert.deepEqual(parseTTYPE(ttype(bytes('A'.repeat(n)))), { ttype: 'A'.repeat(n) });
        }
    });

    test('a 257 byte value is refused', () => {
        assert.equal(errorMessage(parseTTYPE(ttype(bytes('A'.repeat(257))))), 'TTYPE value exceeds maximum length');
    });

    test('an escaped 0xFF (IAC IAC) is refused', () => {
        assert.equal(errorMessage(parseTTYPE(ttype([0x41, IAC, IAC, 0x42]))), 'Invalid TTYPE option structure');
    });

    test('the value ends at the first IAC, which must be followed by SE', () => {
        assert.equal(
            errorMessage(parseTTYPE(Buffer.from([IAC, SB, TTYPE, IS, 0x41, IAC, NOP, IAC, SE]))),
            'Invalid TTYPE option structure'
        );
        //  anything after the first IAC SE is ignored
        assert.deepEqual(parseTTYPE(Buffer.from([IAC, SB, TTYPE, IS, 0x41, IAC, SE, 0x42, IAC, SE])), {
            ttype: 'A',
        });
    });

    test('a wrong header or subcommand is refused', () => {
        [
            [0x00, SB, TTYPE, IS],
            [IAC, 0x00, TTYPE, IS],
            [IAC, SB, NEW_ENVIRON, IS],
            [IAC, SB, TTYPE, SEND],
            [IAC, SB, TTYPE, INFO],
        ].forEach(header => {
            assert.equal(
                errorMessage(parseTTYPE(Buffer.from([...header, 0x41, IAC, SE]))),
                'Invalid TTYPE option structure',
                `${header}`
            );
        });
    });

    test('truncated input is refused', () => {
        [[], [IAC, SB, TTYPE], [IAC, SB, TTYPE, IS, 0x41], [IAC, SB, TTYPE, IS, 0x41, IAC]].forEach(b => {
            assert.equal(
                errorMessage(parseTTYPE(Buffer.from(b))),
                'TTYPE parse error: subnegotiation is truncated',
                `${b}`
            );
        });
    });
});

describe('parseNewEnviron()', () => {
    const environ = (cmd, payload) => Buffer.from([IAC, SB, NEW_ENVIRON, cmd, ...payload, IAC, SE]);
    const result = (vars, uservars, cmd = IS) => ({
        command: cmd,
        commandName: cmd === IS ? 'IS' : 'INFO',
        vars,
        uservars,
    });
    const v = name => [VAR, ...bytes(name)];
    const u = name => [USERVAR, ...bytes(name)];
    const val = value => [VALUE, ...bytes(value)];

    test('an empty list, IS and INFO', () => {
        assert.deepEqual(parseNewEnviron(environ(IS, [])), result([], []));
        assert.deepEqual(parseNewEnviron(environ(INFO, [])), result([], [], INFO));
    });

    describe('orders seen from real clients', () => {
        test('VAR name VALUE value pairs', () => {
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...v('USER'), ...val('bryan'), ...v('DISPLAY'), ...val('host:0')])),
                result([{ USER: 'bryan' }, { DISPLAY: 'host:0' }], [])
            );
        });

        test('USERVAR pairs after VAR pairs', () => {
            assert.deepEqual(
                parseNewEnviron(
                    environ(IS, [
                        ...v('TERM'),
                        ...val('xterm'),
                        ...u('COLUMNS'),
                        ...val('132'),
                        ...u('LINES'),
                        ...val('50'),
                    ])
                ),
                result([{ TERM: 'xterm' }], [{ COLUMNS: '132' }, { LINES: '50' }])
            );
        });

        test('VAR pairs after USERVAR pairs', () => {
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...u('LINES'), ...val('25'), ...v('TERM'), ...val('ansi')])),
                result([{ TERM: 'ansi' }], [{ LINES: '25' }])
            );
        });

        test('an INFO update of one variable', () => {
            assert.deepEqual(
                parseNewEnviron(environ(INFO, [...u('COLUMNS'), ...val('100')])),
                result([], [{ COLUMNS: '100' }], INFO)
            );
        });

        test('an undefined variable last: a name with no VALUE is null', () => {
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...v('TERM'), ...val('ansi'), ...v('TERM_PROGRAM')])),
                result([{ TERM: 'ansi' }, { TERM_PROGRAM: null }], [])
            );
            assert.deepEqual(parseNewEnviron(environ(IS, u('LINES'))), result([], [{ LINES: null }]));
        });

        test('an empty value is null', () => {
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...v('USER'), VALUE, ...u('X'), VALUE])),
                result([{ USER: null }], [{ X: null }])
            );
        });

        test('quirk: an undefined variable before another runs into the next name', () => {
            //  only VALUE or ESC end a name, so the VAR/USERVAR is kept in it
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...v('LINES'), ...v('COLUMNS'), ...val('80')])),
                result([{ 'LINES\x00COLUMNS': '80' }], [])
            );
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...u('LINES'), ...u('COLUMNS'), ...val('80')])),
                result([], [{ 'LINES\x03COLUMNS': '80' }])
            );
        });
    });

    describe('ESC', () => {
        test('escapes VAR, VALUE, ESC and USERVAR in a name', () => {
            assert.deepEqual(
                parseNewEnviron(environ(IS, [VAR, ESC, VAR, ESC, VALUE, ESC, ESC, ESC, USERVAR, ...val('x')])),
                result([{ '\x00\x01\x02\x03': 'x' }], [])
            );
            assert.deepEqual(
                parseNewEnviron(environ(IS, [USERVAR, 0x41, ESC, VALUE, 0x42, ...val('x')])),
                result([], [{ 'A\x01B': 'x' }])
            );
        });

        test('escapes VAR, VALUE, ESC and USERVAR in a value', () => {
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...v('A'), VALUE, ESC, VAR, ESC, VALUE, ESC, ESC, ESC, USERVAR])),
                result([{ A: '\x00\x01\x02\x03' }], [])
            );
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...u('A'), VALUE, ESC, USERVAR, ...v('B')])),
                result([{ B: null }], [{ A: '\x03' }])
            );
        });

        test('an ESC at the very end is dropped', () => {
            assert.deepEqual(parseNewEnviron(environ(IS, [...v('A'), ESC])), result([{ A: null }], []));
            assert.deepEqual(parseNewEnviron(environ(IS, [...v('A'), ...val('x'), ESC])), result([{ A: 'x' }], []));
            assert.deepEqual(parseNewEnviron(environ(IS, [...u('A'), ...val('x'), ESC])), result([], [{ A: 'x' }]));
        });

        test('quirk: a USERVAR name ending in ESC is filed under vars', () => {
            assert.deepEqual(parseNewEnviron(environ(IS, [...u('A'), ESC])), result([{ A: null }], []));
        });
    });

    describe('odd orders', () => {
        test('a second VALUE inside a value is part of it', () => {
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...v('A'), ...val('x'), ...val('y')])),
                result([{ A: 'x\x01y' }], [])
            );
        });

        test('a value with no name is named ""', () => {
            assert.deepEqual(
                parseNewEnviron(environ(IS, [VAR, ...val('x'), ...v('B'), ...val('y')])),
                result([{ '': 'x' }, { B: 'y' }], [])
            );
            assert.deepEqual(parseNewEnviron(environ(IS, [USERVAR, VALUE, VAR])), result([], [{ '': null }]));
        });

        test('quirk: a nameless last entry is dropped, value and all', () => {
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...v('A'), VALUE, VAR, ...val('x')])),
                result([{ A: null }], [])
            );
            assert.deepEqual(parseNewEnviron(environ(IS, [VAR])), result([], []));
            assert.deepEqual(parseNewEnviron(environ(IS, [USERVAR, VALUE])), result([], []));
        });

        test('repeated names are all kept, case sensitive', () => {
            assert.deepEqual(
                parseNewEnviron(environ(IS, [...v('A'), ...val('1'), ...v('A'), ...val('2'), ...v('a'), ...val('3')])),
                result([{ A: '1' }, { A: '2' }, { a: '3' }], [])
            );
        });

        test('names and values are decoded as ascii', () => {
            const decoded = b => Buffer.from(b).toString('ascii');
            assert.deepEqual(
                parseNewEnviron(environ(IS, [VAR, 0xc1, VALUE, 0xe9, 0x80])),
                result([{ [decoded([0xc1])]: decoded([0xe9, 0x80]) }], [])
            );
        });
    });

    describe('refused', () => {
        test('a list not starting with VAR or USERVAR', () => {
            [[VALUE], [ESC], [0x41], [VALUE, ...v('A')]].forEach(payload => {
                assert.equal(
                    errorMessage(parseNewEnviron(environ(IS, payload))),
                    'Invalid NEW-ENVIRON structure',
                    `${payload}`
                );
            });
        });

        test('a command other than IS or INFO', () => {
            [SEND, 3, 0x41].forEach(cmd => {
                assert.equal(
                    errorMessage(parseNewEnviron(environ(cmd, v('A')))),
                    'Invalid NEW-ENVIRON structure',
                    `${cmd}`
                );
            });
        });

        test('an escaped 0xFF (IAC IAC)', () => {
            assert.equal(
                errorMessage(parseNewEnviron(environ(IS, [...v('A'), VALUE, IAC, IAC, 0x41]))),
                'Invalid NEW-ENVIRON structure'
            );
        });

        test('a wrong header', () => {
            [
                [0x00, SB, NEW_ENVIRON, IS],
                [IAC, 0x00, NEW_ENVIRON, IS],
                [IAC, SB, TTYPE, IS],
            ].forEach(header => {
                assert.equal(
                    errorMessage(parseNewEnviron(Buffer.from([...header, IAC, SE]))),
                    'Invalid NEW-ENVIRON structure',
                    `${header}`
                );
            });
        });

        test('truncated input', () => {
            [[], [IAC, SB, NEW_ENVIRON, IS], [IAC, SB, NEW_ENVIRON, IS, VAR, 0x41, IAC]].forEach(b => {
                assert.equal(
                    errorMessage(parseNewEnviron(Buffer.from(b))),
                    'NEW-ENVIRON parse error: subnegotiation is truncated',
                    `${b}`
                );
            });
        });
    });
});
