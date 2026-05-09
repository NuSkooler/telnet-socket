const {
    Commands,
    CommandNames,
    Options,
    OptionNames,
    SubNegotiationCommands
} = require('./telnet_spec');

const { Parser } = require('binary-parser');
const Buffers = require('buffers');
const { Duplex } = require('stream');

const MAX_BUFFER_SIZE  = 65536; //  64 KB — guards against unterminated SB DoS
const MAX_TTYPE_LENGTH = 256;   //  RFC 1091: terminal type names are short

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

const BinaryOptionParsers = {
    TTYPE : new Parser()
        .uint8('iac1')
        .uint8('sb')
        .uint8('opt')
        .uint8('is')
        .array('ttype', {
            type        : 'uint8',
            //  255 = Commands.IAC; constant not avail during parse
            readUntil   : b => 255 === b,  //  IAC is consumed here
        })
        .uint8('se'),

    NEW_ENVIRON : new Parser()
        .uint8('iac1')
        .uint8('sb')
        .uint8('opt')
        .uint8('cmd')   //  IS or INFO
        .array('env', {
            type : 'uint8',
            //  255 = Commands.IAC; constant not avail during parse
            readUntil   : b => 255 === b,   //  IAC is consumed here
        })
        .uint8('se'),
};

const EndSubNegBuffer = Buffer.from([ Commands.IAC, Commands.SE ] );

const OptionParserFactory = {
    [ Options.NAWS ] : (buffers) => {
        //  IAC SB NAWS WIDTH(2) HEIGHT(2) IAC SE
        //  Width/height bytes of 0xFF are escaped as IAC IAC by the sender (RFC 1073 §3),
        //  so the packet may be longer than 9 bytes; find IAC SE to determine the end.
        if (buffers.length < 9) {
            return;
        }

        const endIndex = buffers.indexOf(EndSubNegBuffer, 3); //  past IAC SB NAWS
        if (-1 === endIndex) {
            return; //  more data required
        }

        try {
            const raw = buffers.splice(0, endIndex + EndSubNegBuffer.length).toBuffer();

            if (raw[0] !== Commands.IAC || raw[1] !== Commands.SB || raw[2] !== Options.NAWS) {
                return new Error('Invalid NAWS option structure');
            }

            //  payload is between the 3-byte header and the 2-byte IAC SE trailer
            const payload = unescapeIAC(raw.slice(3, endIndex));
            if (payload.length !== 4) {
                return new Error('Invalid NAWS payload length');
            }

            return {
                width  : payload.readUInt16BE(0),
                height : payload.readUInt16BE(2),
            };
        } catch(e) {
            return new Error(`NAWS parse error: ${e.message}`);
        }
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

        //  IS path: VALUE must be at least one byte, so we need at least 7
        if (buffers.length < 7) {
            return;
        }

        let endIndex = buffers.indexOf(EndSubNegBuffer, 5);   //  past header, find end sub
        if (-1 === endIndex) {
            return; //  more data required
        }

        endIndex += EndSubNegBuffer.length;

        try {
            const buffer = buffers.splice(0, endIndex).toBuffer();
            const ttype = BinaryOptionParsers.TTYPE.parse(buffer);

            if (Commands.IAC !== ttype.iac1 ||
                Commands.SB !== ttype.sb ||
                Options.TTYPE !== ttype.opt ||
                SubNegotiationCommands.IS !== ttype.is ||
                ttype.ttype.length < 1 ||
                Commands.SE !== ttype.se)
            {
                return new Error('Invalid TTYPE option structure');
            }

            ttype.ttype.splice(ttype.ttype.length - 1); //  trim IAC terminator

            if (ttype.ttype.length > MAX_TTYPE_LENGTH) {
                return new Error('TTYPE value exceeds maximum length');
            }

            const ttypeToString = () => {
                let nullPos = ttype.ttype.indexOf(0x00);
                if (-1 == nullPos) {
                    nullPos = ttype.ttype.length;
                }
                return Buffer.from(ttype.ttype.slice(0, nullPos)).toString('ascii');
            };

            const optionData = {
                //  Some terminals such as NetRunner set ttype to a null
                //  terminated buffer. We need to chop off the consumed IAC
                //  terminator as well.
                ttype : ttypeToString(),
            };

            return optionData;
        } catch(e) {
            return new Error(`TTYPE parse error: ${e.message}`);
        }
    },

    [ Options.NEW_ENVIRON ] : (buffers) => {
        //  IAC SB NEW-ENVIRON IS|INFO type... [VALUE ...] [ type ... [ VALUE ... ] [... ] ] IAC SE
        //  thus, we need at least 6 bytes for a empty list of:
        //  IAC SB NEW-ENVIRON IS IAC SE
        if (buffers.length < 6) {
            return;
        }

        let endIndex = buffers.indexOf(EndSubNegBuffer, 4);
        if (-1 === endIndex) {
            return;
        }

        endIndex += EndSubNegBuffer.length;

        try {
            const buffer = buffers.splice(0, endIndex).toBuffer();
            const environ = BinaryOptionParsers.NEW_ENVIRON.parse(buffer);

            if (Commands.IAC !== environ.iac1 ||
                Commands.SB !== environ.sb ||
                Options.NEW_ENVIRON !== environ.opt ||
                (![SubNegotiationCommands.IS, SubNegotiationCommands.INFO].includes(environ.cmd)) ||
                Commands.SE !== environ.se)
            {
                return new Error('Invalid NEW-ENVIRON structure');
            }

            environ.env.splice(environ.env.length - 1); //  trim IAC terminator

            //  name, value, arrays of bytes
            let name = [];
            let value = [];
            let state = 'type';

            const optionData = {
                command     : environ.cmd,
                commandName : environ.cmd === SubNegotiationCommands.IS ? 'IS' : 'INFO',
                vars        : [],
                uservars    : [],
            };

            const appendNameValue = (field) => {
                name = Buffer.from(name).toString('ascii');
                value = Buffer.from(value).toString('ascii');
                optionData[field].push({ [ name ] : value || null });
                name = [];
                value = [];
            };

            for (let i = 0; i < environ.env.length; ++i) {
                const c = environ.env[i];
                switch (state) {
                    case 'type' :
                        if (c === SubNegotiationCommands.USERVAR) {
                            state = 'uservar';
                        } else if (c === SubNegotiationCommands.VAR) {
                            state = 'var';
                        } else {
                            return new Error('Invalid NEW-ENVIRON structure');
                        }
                        break;

                    case 'uservar' :
                    case 'var' :
                        if (c === SubNegotiationCommands.VALUE) {
                            state = `${state}_value`;
                        } else if (c === SubNegotiationCommands.ESC) {
                            state = `${state}_esc`;
                        } else {
                            name.push(c);
                        }
                        break;

                    case 'uservar_esc' :
                        name.push(c);
                        state = 'uservar';
                        break;

                    case 'var_esc' :
                        name.push(c);
                        state = 'var';
                        break;

                    case 'uservar_value' :
                    case 'var_value' :
                        if (c === SubNegotiationCommands.USERVAR) {
                            appendNameValue('uservar_value' === state ? 'uservars' : 'vars');
                            state = 'uservar';
                        } else if (c === SubNegotiationCommands.VAR) {
                            appendNameValue('uservar_value' === state ? 'uservars' : 'vars');
                            state = 'var';
                        } else if (c === SubNegotiationCommands.ESC) {
                            state = `${state}_esc`;
                        } else {
                            value.push(c);
                        }
                        break;

                    case 'uservar_value_esc' :
                        value.push(c);
                        state = 'uservar_value';
                        break;

                    case 'var_value_esc' :
                        value.push(c);
                        state = 'var_value';
                        break;
                }
            }

            if (name.length) {
                //  reached end of buffer with pending name and possibly a value
                const field = (state === 'uservar_value' || state === 'uservar_value_esc' || state === 'uservar')
                    ? 'uservars' : 'vars';
                appendNameValue(field);
            }

            return optionData;
        } catch(e) {
            return new Error(`NEW-ENVIRON parse error: ${e.message}`);
        }
    },
};

const unknownSBParser = (buffers) => {
    //  IAC SB OPTION ... IAC SE
    let endIndex = buffers.indexOf(EndSubNegBuffer, 3); //  past IAC SB OPTION
    if (-1 !== endIndex) {
        endIndex += EndSubNegBuffer.length;
    } else {
        endIndex = 3;   //  try our best to move along
    }
    const raw = buffers.splice(0, endIndex);
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
        this.buffers = Buffers();

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
            this.buffers = Buffers();
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
