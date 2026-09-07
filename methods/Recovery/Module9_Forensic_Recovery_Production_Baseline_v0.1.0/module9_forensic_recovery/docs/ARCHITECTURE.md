# Architecture

                     CASE
                      |
             +--------+--------+
             |        |        |
          identity  config   events
             |        |        |
             +--------+--------+
                      |
                  Acquisition
                      |
               source metadata
                      |
                   SHA-256
                      |
              evidence manifest
                      |
             +--------+--------+
             |                 |
          Analysis         Verification
             |                 |
             +--------+--------+
                      |
                 Audit report

Event chain:
E0 -> hash(E0)
E1 includes hash(E0)
E2 includes hash(E1)
...

This detects accidental alteration/reordering of the case event log.

Important:
event chaining is an integrity mechanism, not a legal guarantee of chain of
custody. Real chain of custody also requires organizational procedures,
authenticated users, protected storage, access controls and jurisdiction-
appropriate handling.
