# Architecture

                    DAMAGED SOURCE
                         |
                         v
                   SourceAdapter
                         |
                         v
                    ReadPolicy
                         |
               +---------+---------+
               |                   |
          large-block pass     known failures
               |                   |
               v                   v
          good regions        split/retry
               |                   |
               +---------+---------+
                         |
                         v
                   Sector Map
                         |
              +----------+----------+
              |                     |
         forward pass          reverse pass
              |                     |
              +----------+----------+
                         |
                         v
                  sector scraping
                         |
                         v
                 immutable image
                         |
                         v
              filesystem/recovery
                    modules

States:
UNKNOWN -> GOOD
UNKNOWN -> FAILED
FAILED  -> RETRYING -> GOOD
FAILED  -> RETRYING -> FAILED
GOOD regions are not reread unless explicitly requested.

The map records sector state, attempts and timing/error counters.
