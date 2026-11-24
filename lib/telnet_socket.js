const {
    Commands,
    CommandNames,
    Options,
    OptionNames,
    SubNegotiationCommands
} = require('./telnet_spec');

const ByteQueue = require('./byte_queue');
const { parseTTYPE, parseNewEnviron } = require('./option_parsers');
const { Duplex } = require('stream');

const MAX_BUFFER_SIZE = 65536; //  64 KB — guards against unterminated SB DoS

//  RFC 854: within subnegotiation payloads, 0xFF bytes are escaped as IAC IAC.
//  This helper unescapes them before further parsing.
const unescapeIAC = (buf) => {
    const out = [];
    for (let i = 0; i < buf.length; i++) {
        out.push(buf[i]);
        if (buf[i] === Commands.IAC && buf[i + 1] === Commands.IAC) {
            i++;
        }
    }
    return Buffer.from(out);
};

const makeCommand = (code, option, optionData) => {
    const optionName = OptionNames[option];
    const command = {
        code,
        option,
        name : CommandNames[code] || 'unknown command',
        optionName : optionName || 'unknown option',
    };
    if (optionData) {
        command.optionData = optionData;
    }
    return command;
};

const EndSubNegBuffer = Buffer.from([ Commands.IAC, Commands.SE ] );

//
//  The index of the IAC SE that ends the subnegotiation at the front of
//  |buffers|, searching from |start| (just past IAC SB OPTION, or past its
//  first payload byte), or -1 if it has not arrived. An escaped 0xFF
//  (IAC IAC) is stepped over, so a payload byte of 0xFF followed by one of
//  0xF0 (SE) is not taken for the end (RFC 854).
//
//  A subnegotiation can arrive a byte at a time, and this is called again
//  for each: where a scan stopped is kept, so each byte is looked at once.
//  It is forgotten when bytes are taken off the queue.
//
const subNegScans = new WeakMap();  //  ByteQueue -> { start, pos, removals }

const findSubNegEnd = (buffers, start) => {
    const scan = subNegScans.get(buffers);
    let i = (scan && scan.start === start && scan.removals === buffers.removals) ? scan.pos : start;
    for (; i + 1 < buffers.length; i++) {
        if (buffers.get(i) !== Commands.IAC) {
            continue;
        }
        const next = buffers.get(i + 1);
        if (next === Commands.SE) {
            subNegScans.delete(buffers);
            return i;
        }
        if (next === Commands.IAC) {
            i++;    //  an escaped 0xFF
        }
    }
    subNegScans.set(buffers, { start, pos : i, removals : buffers.removals });
    return -1;
};

const OptionParserFactory = {
    [ Options.NAWS ] : (buffers) => {
        //  IAC SB NAWS WIDTH(2) HEIGHT(2) IAC SE
        //  Width/height bytes of 0xFF are escaped as IAC IAC by the sender (RFC 1073 §3),
        //  so the packet may be longer than 9 bytes; find IAC SE to determine the end.
        //  A malformed payload can be shorter than 4 bytes, so wait only for IAC SE:
        //  waiting for 9 bytes held back the input that followed it.
        const endIndex = findSubNegEnd(buffers, 3);
        if (-1 === endIndex) {
            return; //  more data required
        }

        //  the header is IAC SB NAWS: this parser is only called for it
        const raw = buffers.splice(0, endIndex + EndSubNegBuffer.length).toBuffer();

        //  payload is between the 3-byte header and the 2-byte IAC SE trailer
        let payload = unescapeIAC(raw.slice(3, endIndex));

        //  NetRunner pads the payload with a NUL before and after it:
        //  IAC SB NAWS 00 WW WW HH HH 00 IAC SE (80x25 arrives as
        //  00 00 50 00 19 00). Read the 4 bytes in the middle.
        if (payload.length === 6 && payload[0] === 0 && payload[5] === 0) {
            payload = payload.slice(1, 5);
        }

        if (payload.length !== 4) {
            return new Error('Invalid NAWS payload length');
        }

        return {
            width  : payload.readUInt16BE(0),
            height : payload.readUInt16BE(2),
        };
    },

    [ Options.TTYPE ] : (buffers) => {
        //  RFC 1091: two sub-command forms:
        //    SEND : IAC SB TTYPE SEND IAC SE          (server→client, request)
        //    IS   : IAC SB TTYPE IS VALUE... IAC SE   (client→server, response)
        if (buffers.length < 6) {
            return;
        }

        const subCmd = buffers.get(3);

        if (subCmd === SubNegotiationCommands.SEND) {
            //  IAC SB TTYPE SEND IAC SE — exactly 6 bytes
            const raw = buffers.splice(0, 6).toBuffer();
            if (raw[0] !== Commands.IAC || raw[1] !== Commands.SB ||
                raw[2] !== Options.TTYPE || raw[3] !== SubNegotiationCommands.SEND ||
                raw[4] !== Commands.IAC  || raw[5] !== Commands.SE)
            {
                return new Error('Invalid TTYPE SEND structure');
            }
            return { send: true };
        }

        //  IS path: IAC SB TTYPE IS VALUE... IAC SE (an empty VALUE is
        //  parsed, and is an empty ttype)
        let endIndex = findSubNegEnd(buffers, 4);
        if (-1 === endIndex) {
            return; //  more data required
        }

        endIndex += EndSubNegBuffer.length;

        return parseTTYPE(buffers.splice(0, endIndex).toBuffer());
    },

    [ Options.NEW_ENVIRON ] : (buffers) => {
        //  IAC SB NEW-ENVIRON IS|INFO type... [VALUE ...] [ type ... [ VALUE ... ] [... ] ] IAC SE
        //  thus, we need at least 6 bytes for a empty list of:
        //  IAC SB NEW-ENVIRON IS IAC SE
        if (buffers.length < 6) {
            return;
        }

        let endIndex = findSubNegEnd(buffers, 4);
        if (-1 === endIndex) {
            return;
        }

        endIndex += EndSubNegBuffer.length;

        return parseNewEnviron(buffers.splice(0, endIndex).toBuffer());
    },
};

const unknownSBParser = (buffers) => {
    //  IAC SB OPTION ... IAC SE: wait for the IAC SE, as the option parsers
    //  do. A stream that never sends one is reset by the MAX_BUFFER_SIZE
    //  guard. (This used to take only IAC SB OPTION when the IAC SE had not
    //  arrived yet, passing the rest on as data, and threw when IAC SB OPTION
    //  were the last 3 bytes buffered.)
    const endIndex = findSubNegEnd(buffers, 3);
    if (-1 === endIndex) {
        return; //  more data required
    }
    const raw = buffers.splice(0, endIndex + EndSubNegBuffer.length);
    return { raw };
};

const willingnessCommandParser = (command, buffers) => {
    //  We expect IAC COMMAND OPTION
    if (buffers.length < 3) {
        return; //  more data required
    }

    const option = buffers.get(2);
    buffers.splice(0, 3);
    return makeCommand(command, option);
};

const CommandFactory = {
    [ Commands.DO ]     : (buffers) => willingnessCommandParser(Commands.DO, buffers),
    [ Commands.DONT ]   : (buffers) => willingnessCommandParser(Commands.DONT, buffers),
    [ Commands.WILL ]   : (buffers) => willingnessCommandParser(Commands.WILL, buffers),
    [ Commands.WONT ]   : (buffers) => willingnessCommandParser(Commands.WONT, buffers),

    [ Commands.SB ] : (buffers) => {
        if (buffers.length < 3) {
            return;
        }

        const option = buffers.get(2);  //  IAC SB OPTION
        const parsed = (OptionParserFactory[option] || unknownSBParser)(buffers);
        if (!parsed) {
            return; //  more data required
        }

        //  consumed from buffers even upon error at this point
        if (parsed instanceof Error) {
            //  emitted as 'command error', with no optionData
            const command = makeCommand(Commands.SB, option);
            command.parsed = parsed;
            return command;
        }
        return makeCommand(Commands.SB, option, parsed);
    }
};

const unknownCommand = (buffers) => {
    const command = buffers.get(1);    //  IAC COMMAND
    buffers.splice(0, 2);
    return makeCommand(command);
};

class Command {
    constructor(name, socket) {
        this.code = Commands[name];
        this.socket = socket;
    }
};

Object.keys(Options).forEach(optionName => {
    const option = Options[optionName];
    Command.prototype[optionName.toLowerCase()] = function() {
        const buffer = Buffer.from([ Commands.IAC, this.code, option ]);
        this.socket.write(buffer);
    };
});


module.exports = class TelnetSocket extends Duplex {
    constructor(socket) {
        super();

        this.socket = socket;
        this.IACBuffer = Buffer.from([ Commands.IAC ]);
        this.EscapedIACBuffer = Buffer.from([Commands.IAC, Commands.IAC]);
        this.buffers = new ByteQueue();

        this.escapeIACs = true;
        this.passthrough = false;

        this._init();
    }

    static commandBuffer(code, option, subNegotiation) {
        //  option may be a plain number or an object with a .code property
        const optCode = (option !== null && typeof option === 'object') ? option.code : option;
        const sequence = [ Commands.IAC, code, optCode ];
        if (Array.isArray(subNegotiation)) {
            sequence.push(...subNegotiation);
        }
        return Buffer.from(sequence);
    }

    command(code, option, subNegotiation) {
        return this.socket.write(TelnetSocket.commandBuffer(code, option, subNegotiation));
    }

    get rawSocket() {
        return this.socket;
    }

    _init() {
        //  wrap socket events
        this.socket.on('close', err => this.emit('close', err));
        this.socket.on('connect', () => this.emit('connect'));
        this.socket.on('drain', () => this.emit('drain'));
        this.socket.on('end', () => this.emit('end'));
        this.socket.on('error', err => this.emit('error', err));

        this.socket.on('lookup', (err, address, family, host) => {
            this.emit('lookup', err, address, family, host);
        });

        this.socket.on('ready', () => this.emit('ready'));
        this.socket.on('timeout', () => this.emit('timeout'));
        this.socket.on('data', data => this._data(data));

        //  Create properties with basic commands, for example:
        //  this.socket.do.ttype()
        ['DO', 'DONT', 'WILL', 'WONT'].forEach( commandName => {
            Object.defineProperty(this, commandName.toLowerCase(),  {
                get             : () => new Command(commandName, this.socket),
                enumerable      : true,
                configurable    : true,
            });
        });

        //  subnegotiation requests (sends), e.g.:
        //  socket.sb.send.ttype()
        this.sb = {
            send :  {
                ttype : () => {
                    return this.command(
                        Commands.SB,
                        Options.TTYPE,
                        [
                            SubNegotiationCommands.SEND,
                            Commands.IAC,
                            Commands.SE,
                        ]
                    );
                },

                new_environ : (variables = [ 'LINES', 'COLUMNS', 'TERM', 'TERM_PROGRAM' ]) => {
                    const subNegotiation = [ SubNegotiationCommands.SEND ];

                    variables.forEach(v => {
                        subNegotiation.push(...[ SubNegotiationCommands.VAR ].concat(v.split('').map(k => k.charCodeAt(0))));
                    });

                    subNegotiation.push(...[ SubNegotiationCommands.USERVAR, Commands.IAC, Commands.SE ]);

                    return this.command(
                        Commands.SB,
                        Options.NEW_ENVIRON,
                        subNegotiation
                    );
                },

                mssp : (keypairs) => {
                    const subNegotiation = [];

                    for (let key in keypairs) {
                        subNegotiation.push(...[ SubNegotiationCommands.MSSP_VAR ].concat(key.split('').map(k => k.charCodeAt(0))));
                        subNegotiation.push(...[ SubNegotiationCommands.MSSP_VAL ].concat(keypairs[key].split('').map(k => k.charCodeAt(0))));
                    }

                    subNegotiation.push(...[ Commands.IAC, Commands.SE ]);

                    return this.command(
                        Commands.SB,
                        Options.MSSP,
                        subNegotiation
                    );
                },

                gmcp : (message, data) => {
                    const subNegotiation = [...message.split('').map(k => k.charCodeAt(0))];

                    if (data) {
                        // 32 is a space character to separate the message from the data
                        subNegotiation.push(...[ 32 ].concat(data.split('').map(k => k.charCodeAt(0))));
                    }

                    subNegotiation.push(...[ Commands.IAC, Commands.SE ]);

                    return this.command(
                        Commands.SB,
                        Options.GMCP,
                        subNegotiation
                    );
                }
            }
        };
    }

    _data(data) {
        if (this.passthrough) {
            return this.push(data);
        }

        this.buffers.push(data);

        if (this.buffers.length > MAX_BUFFER_SIZE) {
            this.buffers = new ByteQueue();
            return this.emit('error', new Error('Telnet buffer overflow: stream reset'));
        }

        let iacIndex;
        let moreDataRequired = false;
        while ((iacIndex = this.buffers.indexOf(this.IACBuffer)) >= 0) {
            //  RFC 854: All commands are at least 2 bytes: IAC CODE
            if (this.buffers.length <= (iacIndex + 1)) {
                moreDataRequired = true;
                break;
            }

            //  flush any non-IAC data that precedes this command
            if (iacIndex > 0) {
                this.push(this.buffers.splice(0, iacIndex).toBuffer());
            }

            //  RFC 854: IAC IAC in the data stream is a literal 0xFF data byte
            if (this.buffers.get(1) === Commands.IAC) {
                this.buffers.splice(0, 2);
                this.push(Buffer.from([ 0xFF ]));
                continue;
            }

            const command = (CommandFactory[this.buffers.get(1)] || unknownCommand)(this.buffers);
            if (!command) {
                moreDataRequired = true;
                break;
            }

            if (command.parsed instanceof Error) {
                this.emit('command error', command, command.parsed);
            } else {
                this.emit(command.name, command);   //  WILL, SB, ...
            }
        }

        if (!moreDataRequired && this.buffers.length > 0) {
            this.push(this.buffers.splice(0).toBuffer());
        }
    }

    _read() {
        //  we have to implement _read() for Duplex, but it doesn't have
        //  to do anything; When the underlying socket itself emits
        //  data, we'll pump it through _data()
    }

    //  note that encoding is not supported
    _write(data, encoding, cb) {
        if (this.passthrough || !this.escapeIACs) {
            return this.socket.write(data, cb);
        }

        //  convert strings to binary Buffers so IAC byte (0xFF) escaping is
        //  byte-accurate rather than matching the Unicode codepoint U+00FF
        if ('string' === typeof data) {
            data = Buffer.from(data, 'binary');
        }

        let iacPos = data.indexOf(Commands.IAC);
        if (-1 === iacPos) {
            return this.socket.write(data, cb);
        }

        //  cork and (mostly) preserve the original write
        this.socket.cork();

        let lastPos = 0;
        while (iacPos > -1) {
            if (iacPos - lastPos > 0) {
                this.socket.write(data.slice(lastPos, iacPos));
            }
            this.socket.write(this.EscapedIACBuffer);
            lastPos = iacPos + 1;
            iacPos = data.indexOf(Commands.IAC, lastPos);
        }

        if (lastPos < data.length) {
            this.socket.write(data.slice(lastPos));
        }

        this.socket.uncork();   //  let the data out

        return cb(null);
    }

    _final(cb) {
        this.socket.end(cb);
    }
};
