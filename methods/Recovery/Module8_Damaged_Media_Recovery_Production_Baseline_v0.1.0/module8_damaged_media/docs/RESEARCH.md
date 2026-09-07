# Module 8 research record

## R-Studio

R-Studio recommends creating an image when bad blocks repeatedly appear so
that subsequent scans/recovery operate on the image rather than the failing
source. Its image workflow supports read retries, a fill pattern for unreadable
sectors, sector-map files and resumable imaging. R-Studio's multi-pass imaging
first copies good areas, identifies bad/slow regions, and later returns to
those regions.

Sources:
https://www.r-studio.com/Unformat_Help/diskimages.html
https://www.r-studio.com/Multipass-imaging-damaged-drives.html
https://www.r-studio.com/Unformat_Help/i_o-monit-and-sector-map-files.html

## DeepSpar

DeepSpar documents read instability, including devices that freeze or become
unresponsive around degraded areas. Its USB Stabilizer can prevent repeated
application retries from repeatedly hitting the source and exposes sector
maps and speed information.

Source:
https://www.deepspar.com/read-instabilities
https://www.deepspar.com/features

Architecture implication:
the engine must classify operations and keep a sector-level map rather than
just retrying a whole large block forever.

## GNU ddrescue

GNU ddrescue is a key reference for mapfile-driven recovery. Its model
separates copying, retrying and scraping so already recovered regions are not
needlessly reread.

Source:
https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html

Architecture implication:
Module 8 uses a persistent sector map and phase/state model.

## HDDSuperClone

HDDSuperClone provides low-level disk reading and recovery-oriented controls.
Its documentation illustrates why specialized hardware/protocol handling
must be kept separate from a generic imaging core.

Source:
https://www.hddsuperclone.com/hddsupertool/manual

## Safety boundary

This package does not issue ATA/SCSI vendor commands, power-cycle drives,
disable firmware features or write to source devices. Those capabilities are
hardware/vendor-specific and belong in a separately audited adapter layer.

## Commercial/IP boundary

No proprietary DeepSpar, MRT, R-Studio, ddrescue or HDDSuperClone source is
copied. The implementation is an original read-only imaging engine based on
publicly documented recovery concepts.
