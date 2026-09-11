"""
Forensic icat JPEG recovery - Phase 5/9
Exercises DREXX build_icat_command on real physical USB (F:)
"""
import sys, subprocess, hashlib, json
sys.path.insert(0, 'D:/DREXX')
from backend_adapters import build_icat_command, build_fls_command, CentralProcessRunner
from pathlib import Path

NATIVE_BIN = Path('D:/DREXX/native_bin')
ICAT_EXE = NATIVE_BIN / 'icat.exe'
FLS_EXE  = NATIVE_BIN / 'fls.exe'
SOURCE = r'\\.\F:'
OUTDIR = Path('D:/DREX_RECOVERED_PHYSICAL_TEST/forensic_icat_jpegs')
OUTDIR.mkdir(parents=True, exist_ok=True)

# All deleted entries from fls (confirmed by fls -f exfat -d \\.\F:)
DELETED_INODES = [
    (8229,  'SIH26149_reconstructed_9_slides.pptx'),
    (8299,  'DM unit-2_rotated.pdf'),
    (8303,  'DM Class work (unit 1)_rotated.pdf'),
    (8308,  'DM unit-2.pdf'),
    (8311,  'DM unit 1-PART A.pdf'),
    (8423,  'problem-statements.pdf'),
    (8470,  'WhatsApp Image 2026-05-20 at 9.20.04 AM.jpeg'),
    (8483,  '24PH205-PIS - Unit -3 Qustion bank-IAT 1 (2) (1).pdf'),
    (8525,  'WhatsApp Image 2026-04-12 at 7.55.57 PM (4).jpeg'),
    (8531,  'WhatsApp Image 2026-04-12 at 7.55.57 PM (3).jpeg'),
    (8537,  'WhatsApp Image 2026-04-12 at 7.55.58 PM (3).jpeg'),
    (8543,  'WhatsApp Image 2026-05-12 at 1.41.53 PM.jpeg'),
    (8548,  'WhatsApp Image 2026-05-12 at 1.41.53 PM (2).jpeg'),
    (8554,  'WhatsApp Image 2026-05-12 at 1.41.49 PM.jpeg'),
    (8577,  'WhatsApp Image 2026-04-12 at 7.55.58 PM (1).jpeg'),
    (8583,  'WhatsApp Image 2026-04-12 at 7.55.58 PM.jpeg'),
    (8606,  'WhatsApp Image 2026-05-10 at 6.10.43 PM (1).jpeg'),
    (8612,  'WhatsApp Image 2026-05-10 at 6.10.43 PM.jpeg'),
    (8617,  'WhatsApp Image 2026-05-10 at 6.10.42 PM.jpeg'),
]

print('=' * 65)
print('PHASE 5/9: Forensic Recovery via DREXX build_icat_command')
print(f'Source: {SOURCE}  (F: SanDisk Ultra, exFAT)')
print(f'Output: {OUTDIR}')
print(f'Deleted entries to recover: {len(DELETED_INODES)}')
print('=' * 65)
print()

recovered = []
failed = []

for inode, name in DELETED_INODES:
    # Use DREXX backend_adapters to construct the command
    cmd = build_icat_command(ICAT_EXE, SOURCE, str(inode), recover_deleted=True)
    print(f'[inode={inode}] {name}')
    print(f'  DREXX build_icat_command -> {cmd}')

    # icat writes raw bytes to stdout - must capture as binary
    proc = subprocess.run(cmd, capture_output=True, timeout=60)
    stderr_str = proc.stderr.decode('utf-8', errors='replace')
    print(f'  Exit: {proc.returncode}  Bytes: {len(proc.stdout)}  Stderr: {stderr_str[:80]!r}')

    if proc.returncode == 0 and len(proc.stdout) > 0:
        # Build safe output filename
        safe_name = (name.replace(':', '_').replace(' ', '_')
                         .replace('(', '').replace(')', ''))
        out_path = OUTDIR / safe_name
        out_path.write_bytes(proc.stdout)

        # Verify magic bytes
        is_jpeg = proc.stdout[:2] == b'\xff\xd8'
        is_pdf  = proc.stdout[:4] == b'%PDF'
        is_pptx = proc.stdout[:4] == b'PK\x03\x04'  # ZIP/PPTX magic

        magic = ('JPEG' if is_jpeg else
                 'PDF'  if is_pdf  else
                 'PPTX/ZIP' if is_pptx else
                 f'UNKNOWN({proc.stdout[:4].hex()})')

        h = hashlib.sha256(proc.stdout).hexdigest().upper()
        print(f'  -> RECOVERED  magic={magic}  size={len(proc.stdout):,} B  SHA256={h[:16]}...')

        recovered.append({
            'inode': inode, 'name': name,
            'output_file': str(out_path),
            'size_bytes': len(proc.stdout),
            'valid_jpeg': is_jpeg,
            'magic': magic,
            'sha256': h,
        })
    else:
        print(f'  -> FAILED  (exit={proc.returncode})')
        failed.append({
            'inode': inode, 'name': name,
            'exit_code': proc.returncode,
            'stderr': stderr_str[:200],
        })
    print()

# Summary
valid_jpegs = [r for r in recovered if r['valid_jpeg']]
valid_pdfs  = [r for r in recovered if r['magic'] == 'PDF']

print('=' * 65)
print('FORENSIC ICAT RECOVERY SUMMARY')
print('=' * 65)
print(f'  Total attempted:      {len(DELETED_INODES)}')
print(f'  Recovered:            {len(recovered)}')
print(f'  Failed:               {len(failed)}')
print(f'  Valid JPEGs:          {len(valid_jpegs)}')
print(f'  Valid PDFs:           {len(valid_pdfs)}')
print(f'  Source (F:) modified: No (icat is read-only)')
print()

if valid_jpegs:
    print('Recovered JPEG files:')
    for r in valid_jpegs:
        print(f'  {r["name"][:60]}  {r["size_bytes"]:,} B  SHA256={r["sha256"][:16]}...')
print()

if failed:
    print('Failed recoveries:')
    for f in failed:
        print(f'  inode={f["inode"]}  {f["name"][:50]}  exit={f["exit_code"]}')

# Save results
results = {
    'source': SOURCE,
    'filesystem': 'exFAT',
    'fls_deleted_entries': len(DELETED_INODES),
    'recovered': recovered,
    'failed': failed,
    'valid_jpegs': len(valid_jpegs),
    'valid_pdfs': len(valid_pdfs),
    'source_modified': False,
}
results_path = OUTDIR / 'icat_results.json'
with open(results_path, 'w') as fp:
    json.dump(results, fp, indent=2)
print(f'Results saved to: {results_path}')
