# Changelog

## [0.2.7] - Unreleased

### Bug Fixes
- A subnegotiation that fails to parse (NAWS, TTYPE, NEW-ENVIRON) is now
  emitted as `'command error'` with the parse error. It used to be emitted
  as `'SB'` with the `Error` as its `optionData`, because the error was
  never attached where `'command error'` looks for it.
- **RFC 1073:** Read NetRunner's NAWS, whose 4-byte payload is padded with a
  NUL on each side (`IAC SB NAWS 00 WW WW HH HH 00 IAC SE`). Any other
  payload length is still rejected.
- **RFC 1073:** A NAWS payload shorter than 4 bytes no longer holds back
  the input after it until 9 bytes have arrived; it is a `'command error'`
  as soon as its `IAC SE` arrives.
- **RFC 1073:** The end of a NAWS is found past escaped 0xFF bytes, so a
  dimension with a 0xFF byte followed by 0xF0 is no longer cut short.

### Changed
- A consumer listening only to `'SB'` no longer sees malformed
  subnegotiations at all; listen to `'command error'` for them.

### Dependencies
- No runtime dependencies. `binary-parser` (whose 3.x is ESM-only) and
  the git dependency `buffers` (`github:NuSkooler/node-buffers`) are
  removed, so installing no longer needs git. TTYPE IS and NEW-ENVIRON are
  parsed by hand and the stream is buffered by an internal byte queue,
  with no behaviour change: the same events, objects and errors for the
  same input. `optionData.raw` on an SB for an option without a parser
  keeps its shape: `length`, `get(i)`, `toBuffer()`, `slice()` and
  `toString()`.

### Tests
- Add `npm test` (`node --test`) with NAWS tests: the 4-byte and padded
  payloads, an escaped 255, a NAWS sent without `WILL NAWS`, rejected
  lengths, a short payload, and a NAWS split across chunks.
- Add characterization tests of what `TelnetSocket` emits and writes:
  every command, TTYPE, NEW-ENVIRON, unknown SBs, IAC escaping both ways,
  commands split byte by byte, and the 64 KB overflow. Add unit tests for
  the byte queue and the TTYPE and NEW-ENVIRON parsers.

## [0.2.6] - 2026-05-08

### Security
- Guard against unterminated `IAC SB` DoS: buffer is reset and an `'error'`
  event is emitted if accumulated stream data exceeds 64 KB
- Cap TTYPE value length at 256 bytes to prevent unbounded string allocation
  from a malicious client
- Fix IAC byte escaping in `_write()` to operate on raw bytes rather than
  the Unicode codepoint U+00FF (ÿ), ensuring binary-accurate 0xFF escaping
- Upgrade `binary-parser` dependency from 1.6.2 to ^2.3.0 (CVE fix)

### RFC Compliance
- **RFC 854:** Unescape `IAC IAC` sequences in `_data()` as literal 0xFF
  data bytes; previously they were treated as unknown commands and dropped,
  silently corrupting binary data
- **RFC 854:** Flush pre-IAC data bytes to the readable side before
  processing each command; previously data preceding an IAC could be
  delayed or misread
- **RFC 1073:** Rewrite NAWS parser to locate `IAC SE` and unescape
  `IAC IAC` within the width/height payload, fixing parsing for terminals
  255 or more columns/rows wide
- **RFC 1091:** Add TTYPE `SEND` receiver in `OptionParserFactory`; previously
  a received SEND request fell through to `unknownSBParser`
- **RFC 1572:** Remove `.toUpperCase()` normalization from NEW-ENVIRON
  variable name parsing; names are case-sensitive per spec

### Bug Fixes
- Fix `sb.send.new_environ()` to encode variable name characters as byte
  values via `charCodeAt(0)`; previously characters were pushed as JS
  strings, encoding as null bytes on the wire
- Fix NEW-ENVIRON end-of-buffer flush to correctly route `uservar`,
  `uservar_value`, and `uservar_value_esc` states to the `uservars` bucket
- Fix `commandBuffer()` option detection to use an explicit `typeof` check
  rather than `isNaN()`, which relied on accidental `undefined` behaviour
- Fix loose equality (`!=`) to strict (`!==`) in NAWS and TTYPE structure
  validation

### RFC Reference Corrections (`telnet_spec.js`)
- Commands block comment: RFC 856 → RFC 854
- `TRANSMIT_BINARY`: RFC 854 → RFC 856
- `EXOPL`: RFC 860 → RFC 861
- `LINEMODE`: RFC 1148 (unrelated) → RFC 1116 / RFC 1184
- `TTYPE`: RFC 930 (obsolete) → RFC 1091
- Header comment: fix duplicate RFC 856 entry; second entry corrected to
  RFC 885 (End of Record); add RFC 1091
- `NEW_ENVIRON_OLD`: clarify origin as RFC 1086, revised RFC 1408

### Other
- Add `SubNegotiationCommands.ENVIRON` and `SubNegotiationCommands.MSSP`
  namespaced sub-objects as aliases for the flat constants, avoiding
  confusion from shared numeric values across namespaces

---

## [0.2.4] - 2022

### Added
- GMCP (Generic MUD Communication Protocol) support
- MSSP (MUD Server Status Protocol) support
- `cork`/`uncork` around IAC escaping in `_write()` to preserve write order
- Static `TelnetSocket.commandBuffer()` helper

---

## [0.2.0]

### Changed
- Refactored to extend Node.js `Duplex` stream

---

## [0.1.x]

- Initial implementation
- NAWS, TTYPE, NEW-ENVIRON subnegotiation support
- DO / DONT / WILL / WONT option negotiation
