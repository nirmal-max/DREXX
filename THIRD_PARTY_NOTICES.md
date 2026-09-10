# DREX recovery backend notices

DREX does not claim a third-party recovery backend is available unless its
locally installed executable and required supporting files are detected.
Source checkouts alone are not bundled executables.

| Backend | Upstream | Role | License notice |
|---|---|---|---|
| TestDisk / PhotoRec | https://github.com/cgsecurity/testdisk | filesystem/partition recovery and carving | GNU GPL v2; retain upstream `COPYING` and source obligations |
| The Sleuth Kit | https://github.com/sleuthkit/sleuthkit | filesystem metadata and forensic analysis | mixed licenses; retain the upstream `licenses/` directory and notices |
| GNU ddrescue | https://savannah.gnu.org/git/?group=ddrescue | failing-media imaging and mapfiles | GNU GPL; retain upstream license and source obligations |
| Autopsy | https://github.com/sleuthkit/autopsy | forensic case workflow | Apache 2.0 plus bundled-component licenses |

The pinned upstream heads audited for this integration were:

- TestDisk: `40e1b8d7830c754203df08f74796d935401632b0`
- The Sleuth Kit: `c71437097f704ac149b60403d2a6ddc8c6a484f4`
- Autopsy: `cb3dacdcad67abe7cf863c74f10dcdb8e25a5c21`

No third-party binary is fabricated or redistributed by the current build.
