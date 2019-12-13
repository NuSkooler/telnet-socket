# telnet-socket
A standards compliant Telnet implementation for Node.js

## Standards
In addition to [RFC 854](https://tools.ietf.org/html/rfc854), a number of additional RFCs, proposed RFCs, and adopted options such as [GMCP](https://www.gammon.com.au/gmcp) are implemented. An emphasis on standards used with ANSI-BBS related terminals is taken, though PRs are certainly welcome if something of use is missing.

_Some_ additional standards include:
* [RFC 856 - Telnet Binary Transmission](https://tools.ietf.org/html/rfc856)
* [RFC 857 - Telnet Echo Option](https://tools.ietf.org/html/rfc857)
* [RFC 858 - Telnet Suppress Go Ahead Option](https://tools.ietf.org/html/rfc858)
* [RFC 1073 - Telnet Window Size Option](https://tools.ietf.org/html/rfc1073)
* [RFC 1091 - Telnet Terminal-Type Option](https://tools.ietf.org/html/rfc1091)
* [RFC 1572 - Telnet Environment Option](https://tools.ietf.org/html/rfc1572)

See [telnet_spec.js](lib/telnet_spec.js) for more information and additional standards.

## Usage
```javascript
const { TelnetSocket, TelnetSpec } = require('telnet-socket');

const telnetSocket = TelnetSocket(rawSocket);

telnetSocket.do.ttype();

telnetSocket.on('WILL', command => {
    switch (command.option) {
        case TelnetSpec.Options.TTYPE :
            telnetSocket.sb.send.ttype();
            break;
    }
});
```

### Events
#### General
* `data` `(data)`: Non-protocol data
* `command error` `(command, error)`: An error ocurred whilest processing a command.
* `end` `()`: Socket `end`.
* `error` `(error)`: A socket error has occurred.

#### Commands
Events are emitted for specific Telnet commands such as (but not limited to) `DO`, `DONT`, `WILL`, `WONT` and `AYT` with the signature of `(command)` where `command` has the following properties:
* `code`: The raw byte code of the command.
* `name`: The command name (`DO`, `DONT`, ...) or `unknown comand`.
* `option`: Option sent with the command.
* `optionName`: The name of the option such as `NAWS` or `unknown option`.

Unknown commands are emitted as `unknown command` with the same signature described above.

## License
See [LICENSE.md](LICENSE)
