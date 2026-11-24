'use strict';

const {
    Commands,
    Options,
    SubNegotiationCommands
} = require('./telnet_spec');

const MAX_TTYPE_LENGTH = 256;   //  RFC 1091: terminal type names are short

//
//  Parsers for a complete TTYPE IS or NEW-ENVIRON subnegotiation, from
//  IAC SB through IAC SE. Each returns its optionData, or an Error.
//
//  Both read the layout binary-parser was once given, and give the same
//  results: IAC SB OPTION COMMAND, the value up to the first IAC at or after
//  byte 4, then the byte after that IAC, which must be SE. An escaped 0xFF
//  (IAC IAC) in the value therefore ends it early and fails the SE check,
//  and anything after that first IAC SE is ignored.
//

const splitSubNegotiation = (buffer) => {
    const end = buffer.indexOf(Commands.IAC, 4);
    if (-1 === end || end + 1 >= buffer.length) {
        return null;    //  no IAC and byte after it: cannot come from TelnetSocket
    }
    return {
        iac     : buffer[0],
        sb      : buffer[1],
        option  : buffer[2],
        command : buffer[3],
        value   : buffer.subarray(4, end),
        se      : buffer[end + 1],
    };
};

//  IAC SB TTYPE IS VALUE... IAC SE
const parseTTYPE = (buffer) => {
    const ttype = splitSubNegotiation(buffer);
    if (!ttype) {
        return new Error('TTYPE parse error: subnegotiation is truncated');
    }

    if (Commands.IAC !== ttype.iac ||
        Commands.SB !== ttype.sb ||
        Options.TTYPE !== ttype.option ||
        SubNegotiationCommands.IS !== ttype.command ||
        Commands.SE !== ttype.se)
    {
        return new Error('Invalid TTYPE option structure');
    }

    if (ttype.value.length > MAX_TTYPE_LENGTH) {
        return new Error('TTYPE value exceeds maximum length');
    }

    //  Some terminals such as NetRunner send a NUL terminated value
    let nullPos = ttype.value.indexOf(0x00);
    if (-1 === nullPos) {
        nullPos = ttype.value.length;
    }

    return {
        ttype : ttype.value.subarray(0, nullPos).toString('ascii'),
    };
};

//  IAC SB NEW-ENVIRON IS|INFO type... [VALUE ...] [ type ... [ VALUE ... ] [... ] ] IAC SE
const parseNewEnviron = (buffer) => {
    const environ = splitSubNegotiation(buffer);
    if (!environ) {
        return new Error('NEW-ENVIRON parse error: subnegotiation is truncated');
    }

    if (Commands.IAC !== environ.iac ||
        Commands.SB !== environ.sb ||
        Options.NEW_ENVIRON !== environ.option ||
        (![SubNegotiationCommands.IS, SubNegotiationCommands.INFO].includes(environ.command)) ||
        Commands.SE !== environ.se)
    {
        return new Error('Invalid NEW-ENVIRON structure');
    }

    //  name, value, arrays of bytes
    let name = [];
    let value = [];
    let state = 'type';

    const optionData = {
        command     : environ.command,
        commandName : environ.command === SubNegotiationCommands.IS ? 'IS' : 'INFO',
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

    for (const c of environ.value) {
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
};

module.exports = {
    parseTTYPE,
    parseNewEnviron,
};
