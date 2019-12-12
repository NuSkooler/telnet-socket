const {
    Commands,
    CommandNames,
    Options,
    OptionNames,
    SubNegotiationCommands
} = require('./telnet_spec');

const { Parser } = require('binary-parser');
const Buffers = require('buffers');

const EventEmitter = require('events');

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
    NAWS : new Parser()
        .uint8('iac1')
        .uint8('sb')
        .uint8('opt')
        .uint16be('width')
        .uint16be('height')
        .uint8('iac2')
        .uint8('se'),

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
        if (buffers.length < 9) {
            return;
        }

        try {
            const naws = BinaryOptionParsers.NAWS.parse(
                buffers.splice(0, 9).toBuffer()
            );

            if (Commands.IAC !== naws.iac1 ||
                Commands.SB !== naws.sb ||
                Options.NAWS !== naws.opt ||
                Commands.IAC !== naws.iac2 ||
                Commands.SE != naws.se)
            {
                return new Error('Invalid NAWS option structure');
            }

            const optionData = {
                width   : naws.width,
                height  : naws.height,
            };

            return optionData;
        } catch(e) {
            return new Error(`NAWS parse error: ${e.message}`);
        }
    },

    [ Options.TTYPE ] : (buffers) => {
        //  IAC SB TTYPE IS VALUE... IAC SE
        //  VALUE must be at least one byte, so we need at least 7
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
                Commands.SE != ttype.se)
            {
                return new Error('Invalid TTYPE option structure');
            }

            ttype.ttype.splice(ttype.ttype.length - 1); //  trim IAC terminator

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
                appendNameValue('uservar_value' === state ? 'uservars' : 'vars');
            }

            return optionData;
        } catch(e) {
            return new Error(`NEW-ENVIRON parse error: ${e.message}`);
        }
    },
};

const unknownOptionParser = (buffers) => {
    const option = buffers.get(2);  //  IAC COMMAND OPTION
    buffers.splice(0, 3);
    return makeCommand(code, option, {});
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
        const parsed = (OptionParserFactory[option] || unknownOptionParser)(buffers);
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

module.exports = class TelnetSocket extends EventEmitter {
    constructor(socket) {
        super();

        this.socket = socket;
        this.buffers = Buffers();
        this.IACBuffer = Buffer.from([ Commands.IAC ]);

        //  Create properties with basic commands, for example:
        //  this.socket.do.ttype()
        ['DO', 'DONT', 'WILL', 'WONT'].forEach( commandName => {
            Object.defineProperty(this, commandName.toLowerCase(),  {
                get             : () => new Command(commandName, this.socket),
                enumerable      : true,
                configurable    : true,
            });
        });

        this.socket.on('data', this.onData.bind(this));

        this.socket.on('end', () => {
            this.emit('end');
        });

        this.socket.on('error', err => {
            this.emit('error', err);
        });

    }

    command(code, option, subNegotiation) {
        //  option object or code is allowed
        const sequence = [ Commands.IAC, code, isNaN(option.code) ? option : option.code ];
        if (Array.isArray(subNegotiation)) {
            sequence.push(...subNegotiation);
        }
        this.socket.write(Buffer.from(sequence));
    }

    requestTermType() {
        return this.command(
            Commands.SB,
            Options.TTYPE,
            [
                SubNegotiationCommands.SEND,
                Commands.IAC,
                Commands.SE,
            ]
        );
    }

    requestEnvironment(variables = [ 'LINES', 'COLUMNS', 'TERM', 'TERM_PROGRAM' ]) {
        const subNegotiation = [ SubNegotiationCommands.SEND ];

        variables.forEach(v => {
            subNegotiation.push(...[ SubNegotiationCommands.VAR ].concat(v.split('')));
        });

        subNegotiation.push(...[ SubNegotiationCommands.USERVAR, Commands.IAC, Commands.SE ]);

        return this.command(
            Commands.SB,
            Options.NEW_ENVIRON,
            subNegotiation
        );
    }

    onData(data) {
        this.buffers.push(data);

        let iacIndex;
        let moreDataRequired = false;
        while ((iacIndex = this.buffers.indexOf(this.IACBuffer)) >= 0) {
            //  RFC 854: All commands are at least 2 bytes: IAC CODE
            if (this.buffers.length <= (iacIndex + 1)) {
                moreDataRequired = true;
                break;
            }

            if (iacIndex > 0) {
                this.emit('data', this.buffers.splice(0, iacIndex).toBuffer());
            }

            const command = (CommandFactory[this.buffers.get(1)] || unknownCommand)(this.buffers);
            if (!command) {
                moreDataRequired = true;
                break;
            }

            if (command.parsed instanceof Error) {
                this.emit('command error', command);
            } else {
                this.emit(command.name, command);   //  WILL, SB, ...
            }

            //  :TODO: emit 'data' for command data??? command.data = consumed buffers -> buffer
        }

        if (!moreDataRequired && this.buffers.length > 0) {
            this.emit('data', this.buffers.splice(0).toBuffer());
        }
    }

    write(data, encoding, cb) {
        //  :TODO: escape any IAC - when do we need to do this to spec?
        //  :TODO: for encoding to really work here, we need iconv for things like CP437 - or perhaps consumers should be responsible
        return this.socket.write(data, encoding, cb);
    }

    rawSocket() {
        return this.socket;
    }
};
