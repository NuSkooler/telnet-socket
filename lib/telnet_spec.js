//
//  A good place to start with the Telnet protocol is Wikipedia:
//  https://en.wikipedia.org/wiki/Telnet
//
//  This Telnet implementation attempts to be "complete enough"
//  to cover what is generally seen out in the wild in relation
//  to Bulletin Board System software and modern terms and MUD
//  clients.
//
//  RFCs of particular interest:
//  - RFC 854   : Telnet Protocol Specification
//  - RFC 856   : Telnet Binary Transmission
//  - RFC 857   : Telnet Echo Option
//  - RFC 858   : Telnet Suppress Go Ahead Option
//  - RFC 859   : Telnet Status Option
//  - RFC 860   : Telnet Timing Mark Option
//  - RFC 861   : Telnet Extended Options: List Option
//  - RFC 885   : Telnet End of Record Option
//  - RFC 1073  : Telnet Window Size Option
//  - RFC 1091  : Telnet Terminal-Type Option (obsoletes RFC 930)
//  - RFC 1572  : Telnet Environment Option (replaces RFC 1408)

const invertNameValues = (obj) => {
    return Object.assign({}, ...Object.entries(obj).map( ([a, b]) => ({[ b ] : a })));
};

const Commands = {
    //  RFC 854
    SE              : 240,  //  Sub negotiation End
    NOP             : 241,  //  No Operation
    DM              : 242,  //  Data Mark
    BRK             : 243,  //  Break
    IP              : 244,  //  Interrupt Process
    AO              : 245,  //  Abort Output
    AYT             : 246,  //  Are You There?
    EC              : 247,  //  Erase Character
    EL              : 248,  //  Erase Line
    GA              : 249,  //  Go Ahead
    SB              : 250,  //  Sub negotiation Begin
    WILL            : 251,  //  Will
    WONT            : 252,  //  Won't
    DO              : 253,  //  Do
    DONT            : 254,  //  Don't
    IAC             : 255,  //  Interpret As Command
};

exports.Commands = Commands;

const CommandNames = invertNameValues(Commands);
exports.CommandNames = CommandNames;

const SubNegotiationCommands = {
    IS      : 0,
    SEND    : 1,
    INFO    : 2,

    VAR     : 0,
    VALUE   : 1,
    ESC     : 2,
    USERVAR : 3,

    MSSP_VAR: 1,
    MSSP_VAL: 2,

    //  Namespaced aliases — preferred for new code; avoids confusion with
    //  IS/SEND/INFO which share numeric values with VAR/VALUE/ESC
    ENVIRON : { VAR: 0, VALUE: 1, ESC: 2, USERVAR: 3 },
    MSSP    : { VAR: 1, VAL: 2 },
};

exports.SubNegotiationCommands = SubNegotiationCommands;

const Options = {
    TRANSMIT_BINARY : 0,    //  RFC 856 - Transmit Binary

    ECHO            : 1,    //  RFC 857 - Echo

    SGA             : 3,    //  RFC 858 - Suppress Go Ahead

    STATUS          : 5,    //  RFC 859 - Status
    TIMING_MARK     : 6,    //  RFC 860 - Timing Mark

    TTYPE           : 24,   //  RFC 1091 - Terminal Type (obsoletes RFC 930)
    EOR             : 25,   //  RFC 885 - End of Record
    TACACS_USER_ID  : 26,   //  RFC 927
    OUTPUT_MARKING  : 27,   //  RFC 933

    NAWS            : 31,   //  RFC 1073 - Negotiate About Window Size

    TERMINAL_SPEED  : 32,   //  RFC 1079 - Terminal Speed

    LINEMODE        : 34,   //  RFC 1116 / RFC 1184 - Linemode Option

    NEW_ENVIRON_OLD : 36,   //  Deprecated; originally RFC 1086, revised RFC 1408. Use NEW_ENVIRON (39)

    ENCRYPT         : 38,   //  RFC 2496 - Telnet Data Encryption Option
    NEW_ENVIRON     : 39,   //  RFC 1572 'NEW-ENVIRON', replaces RFC 1404


    // MUD Server Status Protocol
    // https://mudhalla.net/tintin/protocols/mssp/

    MSSP            : 70,

    //
    //  Generic MUD Communication Protocol (GMCP)
    //  - Technically nonstandard, but generally accepted
    //  - Replaces MUD Server Data Protocol (MSDP)
    //  - JSON data driven
    //
    //  https://tintin.sourceforge.io/protocols/gmcp/
    //  https://www.gammon.com.au/gmcp
    //
    GMCP            : 201,

    EXOPL           : 255,  //  RFC 861 - Extended Options List
};

exports.Options = Options;

const OptionNames = invertNameValues(Options);
exports.OptionNames = OptionNames;
