# Source / software research matrix

| Software / standard | Role in research | Public source / official reference | Reuse decision |
|---|---|---|---|
| NIST SP 800-88 Rev. 2 | Policy authority | https://csrc.nist.gov/pubs/sp/800/88/r2/final | Follow as normative policy reference |
| IEEE 2883-2022 | Technology-specific sanitization standard | https://standards.ieee.org/ieee/2883/10277/ | Invoke through approved adapters; standard text is not copied |
| IEEE 2883.1-2025 | Recommended practice for using sanitization methods | https://standards.ieee.org/ieee/2883/10277/ | Reference for deployment policy |
| nvme-cli | NVMe native sanitize implementation/reference | https://github.com/linux-nvme/nvme-cli | External execution dependency or adapter reference |
| Microsoft SDelete | Windows file/free-space reference | https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete | Behavioral/reference study; not copied |
| DriveWipe | Modern open-source architecture/reference | https://github.com/KodyDennon/DriveWipe | Review license and code before any reuse |
| Eraser | Open-source Windows erasure-method reference | https://github.com/gtrant/eraser | GPL source; do not copy into incompatible proprietary module |
| GNU shred | POSIX overwrite reference | https://www.gnu.org/software/coreutils/manual/html_node/shred-invocation.html | Behavioral/reference study |

## Licensing note

This package does not bundle third-party source code. That is intentional.
Commercial integration should use compatible licenses, separate processes/binaries,
or clean-room reimplementation where necessary.
