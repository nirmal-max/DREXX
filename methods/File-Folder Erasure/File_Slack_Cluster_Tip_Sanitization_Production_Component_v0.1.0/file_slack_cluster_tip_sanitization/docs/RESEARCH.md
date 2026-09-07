# Deep research

## NIST SP 800-88 Rev. 2
The current final revision was published September 26, 2025. NIST frames sanitization
around making access to target data infeasible for a given level of effort and points
technique selection toward current standards such as IEEE 2883, NSA specifications,
or an approved organizational standard. It does not prescribe a universal file-slack
algorithm.

## Microsoft SDelete
SDelete v2.06 (published March 2026) explains that NTFS compressed, encrypted and sparse
files can allocate new clusters when overwritten. It uses the Windows defragmentation
API to determine physical clusters for special files. For free-space cleansing it
avoids directly racing the filesystem allocator and instead allocates large files to
consume free space. It also explains that free directory space containing deleted names
cannot be allocated and therefore is not covered by ordinary free-space cleaning.

Engineering consequence: do not infer physical cluster locations from logical EOF
alone.

## Eraser
The open-source Eraser project is a mature Windows secure-erasure reference for
filesystem-aware operations. No third-party source is copied.

## GNU shred
GNU documentation warns that filesystem behavior, snapshots, copy-on-write, RAID,
compression, journaling and backups can defeat assumptions that a logical overwrite
covers every physical representation.

## Storage technology
On SSD/NVMe, even a correct logical cluster-tip write does not prove physical-media
purge because flash translation and remapping can retain old physical representations.

## Verification
Zero pattern can be verified exactly when the backend has a proven target region.
Random pattern can be verified for successful readable output, but exact byte equality
requires retaining the generated stream. This package does not make a stronger claim.
