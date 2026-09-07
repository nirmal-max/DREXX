# Commercial release gates

Required before commercial release:
- controlled RAID0/1/5/6/10 corpus
- vendor RAID metadata corpus
- md RAID 0.90/1.0/1.1/1.2 fixtures
- NAS layouts including Synology/QNAP/Buffalo-style configurations
- nested RAID 10/50/60
- 4K sector member tests
- uneven member-size tests
- degraded RAID5/6 tests
- parity verification against independent implementations
- automatic order/stripe-size candidate search
- filesystem-signature scoring on reconstructed virtual media
- performance testing at multi-terabyte scale
- crash-safe export/resume
