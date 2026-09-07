# Security

- member sources are opened read-only
- no mdadm/controller commands are executed
- no member writes
- missing disks are represented by explicit placeholders
- all logical-to-physical mappings are bounds checked
- parity operations are bounded
- output is always a separate file
- malformed metadata fails closed

Commercial release gates:
- fuzz member metadata
- fuzz layout configurations
- property-test parity identities
- test very large sparse images
- test interrupted exports
- ASan/UBSan
- Windows verifier
- corruption and bad-sector simulation
- differential testing against known RAID fixtures
