# DREXX — F:\ Drive 9-File Erasure Evidence

> Generated: 2026-09-12T03:18:18.065725+00:00

## Target Files & Methods

| # | File | Method | Size | SHA-256 Before | SHA-256 After | File Gone | Status | Duration |
|---|------|--------|------|----------------|---------------|-----------|--------|----------|
| 1 | `stock_sentiment.py` | #8 CSPRNG Random Overwrite | 23,446 B | `78D57E7D2218D0C0…` | `FILE_ERASED` | YES | **PASS** | 0.12s |
| 2 | `THE  PITCH DECK (1) (1).pdf` | #14 Single-Pass Zero Overwrite | 4,452,732 B | `43E13DC46842624C…` | `FILE_ERASED` | YES | **PASS** | 0.54s |
| 3 | `THE  PITCH DECK (1) (2).pdf` | #11 Filesystem Metadata Sanitization | 4,452,732 B | `43E13DC46842624C…` | `43E13DC46842624C…` | no | **PASS** | 0.02s |
| 4 | `Unit1 Full Subheadings Keyword Summary Notes.pdf` | #16 Temporary / Cache Purge | 36,530 B | `1ECCD47628F08AC4…` | `FILE_ERASED` | YES | **PASS** | 0.04s |
| 5 | `Unit1 Full Subheadings Keyword Summary Notes (1).pdf` | #8 CSPRNG Random Overwrite | 36,528 B | `3CCB1A31EAAD8365…` | `FILE_ERASED` | YES | **PASS** | 0.03s |
| 6 | `Unit1dpcoquestionwithanswerpdf.pdf` | #14 Single-Pass Zero Overwrite | 1,212,108 B | `B329204D89EE9960…` | `FILE_ERASED` | YES | **PASS** | 0.1s |
| 7 | `Updated NPTEL list on 16.08.26 @ 8am.xlsx` | #11 Filesystem Metadata Sanitization | 615,421 B | `7B04BAAD7F3D06FC…` | `7B04BAAD7F3D06FC…` | no | **PASS** | — |
| 8 | `Updated NPTEL Course Paid and unpaid list-19.08.2026.xlsx` | #16 Temporary / Cache Purge | 618,139 B | `D51C2695F60642ED…` | `FILE_ERASED` | YES | **PASS** | 0.05s |
| 9 | `UAP-PURSUE-Release01-COMPLETE.zip` | #8 CSPRNG Random Overwrite | 1,669,093,693 B | `0B4006EA40D1F8F0…` | `FILE_ERASED` | YES | **PASS** | 137.31s |

## Error Details

None — all 9 files erased successfully.

## Raw JSON

```json
[
  {
    "file_num": 1,
    "method_id": "csprng",
    "method_label": "CSPRNG Random Overwrite",
    "method_number": "#8",
    "filename": "stock_sentiment.py",
    "path": "F:\\stock_sentiment.py",
    "size_bytes": 23446,
    "sha256_before": "78D57E7D2218D0C0AFD0F4EC07D1ABAB80022610B6D3D48293662BDD3EEFD2AB",
    "sha256_after": "FILE_ERASED",
    "file_exists_after": false,
    "status": "PASS",
    "error": null,
    "duration_s": 0.12,
    "result": {
      "verified": true,
      "removed": true,
      "sha256_after": null
    }
  },
  {
    "file_num": 2,
    "method_id": "zero",
    "method_label": "Single-Pass Zero Overwrite",
    "method_number": "#14",
    "filename": "THE  PITCH DECK (1) (1).pdf",
    "path": "F:\\THE  PITCH DECK (1) (1).pdf",
    "size_bytes": 4452732,
    "sha256_before": "43E13DC46842624C9A3BFF9EF0D1CDD6DE801716513CE1A61E7DD5C7F3A8833D",
    "sha256_after": "FILE_ERASED",
    "file_exists_after": false,
    "status": "PASS",
    "error": null,
    "duration_s": 0.54,
    "result": {
      "verified": true,
      "removed": true,
      "sha256_after": null
    }
  },
  {
    "file_num": 3,
    "method_id": "metadata",
    "method_label": "Filesystem Metadata Sanitization",
    "method_number": "#11",
    "filename": "THE  PITCH DECK (1) (2).pdf",
    "path": "F:\\THE  PITCH DECK (1) (2).pdf",
    "size_bytes": 4452732,
    "sha256_before": "43E13DC46842624C9A3BFF9EF0D1CDD6DE801716513CE1A61E7DD5C7F3A8833D",
    "sha256_after": "43E13DC46842624C9A3BFF9EF0D1CDD6DE801716513CE1A61E7DD5C7F3A8833D",
    "file_exists_after": true,
    "status": "PASS",
    "error": null,
    "duration_s": 0.02,
    "result": {
      "verified": true,
      "removed": false,
      "sha256_after": "43e13dc46842624c9a3bff9ef0d1cdd6de801716513ce1a61e7dd5c7f3a8833d"
    }
  },
  {
    "file_num": 4,
    "method_id": "temporary",
    "method_label": "Temporary / Cache Purge",
    "method_number": "#16",
    "filename": "Unit1 Full Subheadings Keyword Summary Notes.pdf",
    "path": "F:\\Unit1 Full Subheadings Keyword Summary Notes.pdf",
    "size_bytes": 36530,
    "sha256_before": "1ECCD47628F08AC40F16D317646A8AC0482555EA5EB18EBEC3B4899778B7989F",
    "sha256_after": "FILE_ERASED",
    "file_exists_after": false,
    "status": "PASS",
    "error": null,
    "duration_s": 0.04,
    "result": {
      "verified": true,
      "removed": true,
      "sha256_after": null
    }
  },
  {
    "file_num": 5,
    "method_id": "csprng",
    "method_label": "CSPRNG Random Overwrite",
    "method_number": "#8",
    "filename": "Unit1 Full Subheadings Keyword Summary Notes (1).pdf",
    "path": "F:\\Unit1 Full Subheadings Keyword Summary Notes (1).pdf",
    "size_bytes": 36528,
    "sha256_before": "3CCB1A31EAAD83659391890D44F60207FD1CC765A3653213F30879F8AE566493",
    "sha256_after": "FILE_ERASED",
    "file_exists_after": false,
    "status": "PASS",
    "error": null,
    "duration_s": 0.03,
    "result": {
      "verified": true,
      "removed": true,
      "sha256_after": null
    }
  },
  {
    "file_num": 6,
    "method_id": "zero",
    "method_label": "Single-Pass Zero Overwrite",
    "method_number": "#14",
    "filename": "Unit1dpcoquestionwithanswerpdf.pdf",
    "path": "F:\\Unit1dpcoquestionwithanswerpdf.pdf",
    "size_bytes": 1212108,
    "sha256_before": "B329204D89EE99601F03085B442DECAEA886AD28706AF914A56E3E9CE12ECF6E",
    "sha256_after": "FILE_ERASED",
    "file_exists_after": false,
    "status": "PASS",
    "error": null,
    "duration_s": 0.1,
    "result": {
      "verified": true,
      "removed": true,
      "sha256_after": null
    }
  },
  {
    "file_num": 7,
    "method_id": "metadata",
    "method_label": "Filesystem Metadata Sanitization",
    "method_number": "#11",
    "filename": "Updated NPTEL list on 16.08.26 @ 8am.xlsx",
    "path": "F:\\Updated NPTEL list on 16.08.26 @ 8am.xlsx",
    "size_bytes": 615421,
    "sha256_before": "7B04BAAD7F3D06FC4B712808CCFFD677E88E98E2149605BA0115A3E872297A4C",
    "sha256_after": "7B04BAAD7F3D06FC4B712808CCFFD677E88E98E2149605BA0115A3E872297A4C",
    "file_exists_after": true,
    "status": "PASS",
    "error": null,
    "duration_s": 0.0,
    "result": {
      "verified": true,
      "removed": false,
      "sha256_after": "7b04baad7f3d06fc4b712808ccffd677e88e98e2149605ba0115a3e872297a4c"
    }
  },
  {
    "file_num": 8,
    "method_id": "temporary",
    "method_label": "Temporary / Cache Purge",
    "method_number": "#16",
    "filename": "Updated NPTEL Course Paid and unpaid list-19.08.2026.xlsx",
    "path": "F:\\Updated NPTEL Course Paid and unpaid list-19.08.2026.xlsx",
    "size_bytes": 618139,
    "sha256_before": "D51C2695F60642ED0628639745ABC9737AF906231BEEFDADF84E8F5E41C967D1",
    "sha256_after": "FILE_ERASED",
    "file_exists_after": false,
    "status": "PASS",
    "error": null,
    "duration_s": 0.05,
    "result": {
      "verified": true,
      "removed": true,
      "sha256_after": null
    }
  },
  {
    "file_num": 9,
    "method_id": "csprng",
    "method_label": "CSPRNG Random Overwrite",
    "method_number": "#8",
    "filename": "UAP-PURSUE-Release01-COMPLETE.zip",
    "path": "F:\\UAP-PURSUE-Release01-COMPLETE.zip",
    "size_bytes": 1669093693,
    "sha256_before": "0B4006EA40D1F8F009E70C069C0532D3799B48E44615D7FFBB0D94E568CE3A8D",
    "sha256_after": "FILE_ERASED",
    "file_exists_after": false,
    "status": "PASS",
    "error": null,
    "duration_s": 137.31,
    "result": {
      "verified": true,
      "removed": true,
      "sha256_after": null
    }
  }
]
```
