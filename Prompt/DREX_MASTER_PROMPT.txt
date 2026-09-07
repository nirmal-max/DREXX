# DREX — MASTER PRODUCTION BUILD PROMPT FOR CODEX

## ROLE

Act as the lead software engineer, product engineer, Windows desktop engineer, security-focused engineer, QA engineer, build/release engineer, and installer engineer for the DREX project.

Your job is to turn the supplied DREX repository + supplied Architecture package + supplied UI references into a real, working, production-quality, commercially distributable, fully offline Windows desktop application.

Do not treat this as a mockup, prototype, demonstration, proof of concept, static UI, or documentation exercise.

The final objective is a working DREX Windows application and a conventional Windows installer:

`DREX-Setup.exe`

created with **Inno Setup**.

---

# 1. INPUTS — USE ALL OF THEM

You have three authoritative inputs.

## INPUT A — DREX GitHub repository

Repository:

`https://github.com/nirmal-max/DREX.git`

The repository contains the existing DREX sanitization, recovery, supporting, testing, and native implementation work.

### Rules

- Inspect the entire repository before deciding what to implement.
- Reuse and integrate existing functional implementations wherever appropriate.
- Do not unnecessarily rewrite working methods.
- Do not duplicate an existing method merely because it exists in multiple repository layers.
- If an existing implementation is incomplete, unsafe, simulated, stubbed, hardware-gated, or unsuitable for production, identify that explicitly and implement the missing integration/hardening required for a truthful product.
- Never represent a simulation as a real destructive operation.
- Never claim real hardware qualification merely because unit tests pass.

The repository is the implementation source.

---

## INPUT B — Architecture package

The supplied `Architecture` package is the product/UI/behavior specification.

Read the entire package before implementation, including:

- `CODEX_HANDOFF.md`
- `DECISIONS.md`
- `README.md`
- `UI DESIGN/`
- `Window/`
- `Window/Page Window/`
- `Certificate/`
- `.obsidian/`

The following are particularly important:

### UI references

Use the supplied UI images as the visual source of truth:

- Dashboard Page
- Wipe Drive Page
- Wipe File Folder Page
- Destroy Drive Page
- Certificate Page
- Certificate reference image

Preserve the DREX visual identity, hierarchy, navigation structure, information hierarchy, method-card structure, operation-log presentation, progress presentation, certificate centre and Help Center.

Do not replace the supplied UI with a generic dashboard.

### Certificate reference

`Certificate/DREX Certificate Reference.png`

is the authoritative visual reference for the certificate.

`Certificate/CERTIFICATE_SPECIFICATION.md`

is the authoritative certificate behavior specification.

---

## INPUT C — This master prompt

This prompt defines the execution objective, integration rules, quality gate, testing requirements, and final deliverables.

Where implementation details are not specified, make sound engineering decisions yourself.

Do not ask the developer to design your technical architecture.

---

# 2. CORE PRODUCT REQUIREMENT

Build DREX as a complete Windows desktop application.

DREX must be:

- fully offline during normal operation;
- installable as a conventional Windows application;
- capable of integrating the existing DREX methods;
- visually based on the supplied UI;
- capable of performing the supported operations for which real implementations exist;
- truthful about hardware capability and operation results;
- locally auditable;
- capable of generating accurate certificates;
- packaged with Inno Setup.

The final user experience should be comparable to a normal professional Windows desktop application.

The user should be able to download:

`DREX-Setup.exe`

run it, see a professional installer, install DREX, optionally launch it, and then use the installed DREX application.

---

# 3. DO NOT DESIGN A FAKE PRODUCT

Do not create:

- fake erasure progress;
- fake device information;
- fake recovery results;
- fake verification;
- fake certificates;
- hard-coded success;
- hard-coded device lists;
- placeholder buttons that appear functional;
- simulated hardware operations presented as real operations;
- fabricated hashes;
- fabricated signatures;
- fabricated QR validation;
- fabricated public-key fingerprints;
- fabricated operation logs.

If something cannot actually be performed, the UI must say so accurately and safely.

---

# 4. TECHNICAL ARCHITECTURE — YOU DECIDE

You are responsible for determining the appropriate technical architecture.

Do not ask the developer to choose:

- frontend framework;
- backend/core architecture;
- language boundaries;
- IPC;
- process model;
- state management;
- database technology;
- native integration strategy;
- packaging details;
- build orchestration.

Choose an architecture that is maintainable, testable, secure, and appropriate for a Windows desktop application with low-level storage-device operations.

Conceptually keep responsibilities separated:

```text
DREX UI
   ↓
Application / Orchestration Layer
   ↓
Policy + Capability Layer
   ↓
Method Adapters
   ↓
Existing DREX Implementations
   ↓
Execution
   ↓
Verification
   ↓
Certificate / Audit
   ↓
Local Storage
```

The UI must not directly contain low-level sanitization/recovery implementation logic.

---

# 5. IMPLEMENT THE UI FROM THE SUPPLIED DESIGNS

The supplied Canva/UI reference is not merely inspiration.

Treat it as the intended product appearance.

Implement the visual structure faithfully:

- DREX branding;
- logo placement;
- sidebar;
- navigation labels;
- page headings;
- cards;
- method cards;
- buttons;
- status indicators;
- device/file information;
- logs;
- progress bar;
- certificate centre;
- Help Center;
- system-health area;
- recent activity;
- security highlights.

Do not redesign the application into a different product.

Small implementation changes are allowed when necessary for usability, responsiveness, accessibility, or technical correctness, but preserve the intended visual language.

---

# 6. MAIN NAVIGATION

The sidebar must contain:

1. Dashboard
2. Wipe Drive
3. Wipe File/Folder
4. Recover
5. Destroy Drive
6. Certificates
7. Help

The Dashboard is the default page.

---

# 7. DASHBOARD

Display the supplied Dashboard design.

Statistics:

- Drives Wiped
- Files/Folders Wiped
- Files Recovered
- Certificates

Do NOT create a "Destroyed Drives" statistic.

Reason:

**Destroy Drive is informational/assessment only and does not physically destroy devices.**

Also provide the dashboard elements represented in the UI reference:

- operation shortcuts;
- detected storage devices;
- System Health;
- Recent Activity;
- Security Highlights;
- DREX version/branding.

Statistics must come from real local operation records, not hard-coded values.

---

# 8. WIPE DRIVE

Purpose:

Securely sanitize an entire storage device using the selected supported method.

## Device information

Show relevant detected information including:

- Model
- Serial Number
- Capacity
- Interface
- Drive Letter
- Device ID
- Health

Use actual device information where available.

Do not fabricate unavailable fields.

## Seven user-facing methods

Display exactly:

1. **NIST SP 800-88 Rev.2**
   - Erase with trusted, standards-based assurance.

2. **Smart Sanitization**
   - Let DREX choose the safest method for you.

3. **Device-Native Sanitize**
   - Use your drive's built-in secure sanitization.

4. **ATA Secure Erase**
   - Securely clear compatible SATA drives.

5. **NVMe Secure Erase**
   - Securely sanitize your NVMe drive.

6. **IEEE 2883 Purge**
   - Achieve strong, technology-aware purge assurance.

7. **Verified Overwrite**
   - Overwrite your data and verify the result.

Only one method may be selected at a time.

## Execution flow

```text
Select device
 ↓
Show device information
 ↓
Select one method
 ↓
Validate target
 ↓
Check method/device capability
 ↓
Require appropriate confirmation
 ↓
Execute real supported method
 ↓
Show live operation log
 ↓
Show progress
 ↓
Perform required verification
 ↓
Determine truthful result
 ↓
Generate certificate only when certificate conditions are satisfied
 ↓
Update local history/statistics
```

Never silently change the user's selected method.

If a method cannot safely operate on the target:

- stop safely;
- explain why;
- do not claim success;
- do not silently downgrade;
- if a method explicitly supports a safe fallback, clearly show that behavior to the user.

---

# 9. WIPE FILE/FOLDER

Purpose:

Securely sanitize selected files/folders using the selected method.

## Target information

Show:

- Filename
- File Type
- Location
- Size
- Size on Disk

Provide appropriate browse/file-selection behavior.

## Nine user-facing methods

Display exactly:

1. **CSPRNG Random Overwrite**
   - Replace sensitive files with unpredictable data.

2. **Cryptographic Erasure**
   - Make protected data permanently inaccessible.

3. **File Slack / Cluster-Tip Sanitization**
   - Clear hidden remnants around your files.

4. **Filesystem Metadata Sanitization**
   - Remove exposed traces left by the filesystem.

5. **NIST SP 800-88 Policy Engine**
   - Choose a policy-backed sanitization strategy.

6. **Secure Free-Space Wiping**
   - Clear recoverable traces from unused space.

7. **Single-Pass Zero Overwrite**
   - Clean selected files with a verified zero overwrite.

8. **Storage-Aware Sanitization & Fallback**
   - Automatically choose the safest available path.

9. **Temporary / Cache Sanitization**
   - Clear temporary files and residual traces.

Only one method may be selected at a time.

## Repository duplication rule

The repository may contain multiple layers/versions related to filesystem metadata sanitization.

Expose this as ONE user-facing method:

`Filesystem Metadata Sanitization`

Do not create duplicate method cards simply because multiple internal implementations exist.

---

# 10. RECOVERY

Purpose:

Recover deleted/lost data using the existing recovery implementations.

Nine user-facing methods:

1. **Quick Recovery**
   - Find recently deleted data quickly.

2. **Smart Recovery**
   - Let DREX find the best recovery path.

3. **Targeted Recovery**
   - Recover exactly what you're looking for.

4. **Filesystem Recovery**
   - Restore data from damaged filesystem structures.

5. **Deep Recovery**
   - Search deeper for lost and deleted data.

6. **Fragment Recovery**
   - Reconstruct files from scattered data fragments.

7. **Storage / RAID Recovery**
   - Recover data from complex storage configurations.

8. **Damaged Media Recovery**
   - Recover what's possible from damaged media.

9. **Forensic Recovery**
   - Recover and analyze data for forensic investigation.

Only one method may be selected at a time.

## Recovery flow

```text
Select target
 ↓
Show relevant target/device properties
 ↓
Select one recovery method
 ↓
Validate target
 ↓
Validate method/capability
 ↓
Start recovery
 ↓
Show live Recovery Log
 ↓
Show progress
 ↓
Present actual recovered results
 ↓
Generate truthful recovery certificate
 ↓
Store local operation record
```

Recovery MUST have:

- operation log;
- progress bar;
- success/error state;
- result presentation.

Do not pretend files were recovered when they were not.

---

# 11. DESTROY DRIVE — LOCKED DECISION

This is critical.

**Destroy Drive is NOT a physical destruction feature.**

It is an informational/device-assessment page only.

Do not implement physical destruction.

Do not add a destructive physical-destruction button.

Do not execute a hardware destruction command.

Do not provide unsafe physical destruction instructions.

Do not generate a certificate claiming DREX physically destroyed the drive.

## Destroy Drive behavior

```text
Open Destroy Drive
 ↓
Detect/select device
 ↓
Assess device type/capability
 ↓
Display:
  - Device Type
  - Capacity
  - Serial Number
  - Supported Erasure Methods
  - Current Recommendation
 ↓
If no applicable software method exists:
  explain the limitation
  recommend appropriate alternative sanitization
  or authorized/certified disposal
```

The supplied Destroy Drive UI is the visual reference.

The safety warning must remain clear.

The page should never claim:

`DATA SUCCESSFULLY DESTROYED`

because DREX is not physically destroying anything on this page.

---

# 12. PROPERTIES COMPONENT

## Drive properties

Where relevant show:

- Model
- Serial Number
- Capacity
- Interface
- Drive Letter
- Device ID
- Health

## File/folder properties

Where relevant show:

- Filename
- File Type
- Location
- Size
- Size on Disk

Use real data.

If a field is unavailable, show an honest unavailable state instead of inventing a value.

---

# 13. OPERATION LOG

Wipe Drive, Wipe File/Folder and Recovery must provide a live operation log.

Example:

```text
[16:15:49] Detecting device...
[16:15:50] Checking capabilities...
[16:15:51] Operation started...
[16:15:53] Verification started...
[16:15:55] Verification completed.
```

The log must reflect actual application events.

Do not generate fake progress messages unrelated to actual work.

Logs should support troubleshooting and auditability.

---

# 14. PROGRESS

Show real progress where meaningful.

States should distinguish at least:

- Running
- Successful
- Failed
- Cancelled
- Verification failed

Successful state:

`SUCCESS`

Failure state:

`ERROR OCCURRED`

The UI should match the supplied visual reference.

---

# 15. CERTIFICATE SYSTEM

The certificate is a real DREX product component.

Use:

`Certificate/DREX Certificate Reference.png`

as the visual template.

Use:

`Certificate/CERTIFICATE_SPECIFICATION.md`

as the behavior specification.

## Certificate generation flow

```text
Operation
 ↓
Execution
 ↓
Verification
 ↓
Determine actual result
 ↓
Certificate generation
 ↓
Populate real operation data
 ↓
Generate QR validation information
 ↓
Generate digital signature information
 ↓
Create PDF
 ↓
Store locally
 ↓
Display in Certificate Centre
```

## Certificate fields

Include the visual/reference sections:

### Header

- DREX Certificate of Data Destruction
- Tamper-Proof Digital Certificate
- Certificate ID
- Issue timestamp in UTC

### Device Information

- Device Path
- Device Type
- Device Model
- Serial Number
- Drive Size

### Operation Details

- Method
- Passes where applicable
- Started
- Completed
- Duration
- Status

### Verification Data

- SHA-256 Before
- SHA-256 After
- Verification result

### Scan to Verify

- QR code
- Certificate validation information / Certificate ID as appropriate

### Digital Signature

- Signature Hash
- Public Key Fingerprint

### Footer/legal information

Use the supplied reference as the visual guide.

## Truthfulness rule

Replace placeholders using actual data.

Never fabricate:

- hashes;
- signatures;
- fingerprints;
- certificate IDs;
- timestamps;
- operation status;
- verification results;
- QR payload.

## Wording rule

The certificate must describe what actually happened.

For drive/file sanitization, use sanitization/erase terminology.

For recovery, use recovery terminology.

Do not use physical-destruction wording for software sanitization.

The reference phrase:

`DATA SUCCESSFULLY DESTROYED`

must therefore be dynamic/appropriate to the actual operation.

For example:

`DATA SUCCESSFULLY SANITIZED`

for a successful software sanitization operation.

Recovery certificates should use recovery wording.

## Failed operation rule

A failed, cancelled, or unverified operation must never produce a certificate that claims successful completion.

If an audit record is retained for a failed operation, mark it clearly as:

- Failed
- Cancelled
- Partial
- Verification Failed

as appropriate.

Never represent it as successful sanitization.

## Destroy Drive rule

Destroy Drive does not create a destruction certificate.

---

# 16. TAMPER-EVIDENT / CRYPTOGRAPHIC CERTIFICATE DESIGN

Implement the certificate's cryptographic fields using a sound local design.

The certificate should be internally consistent and verifiable offline.

The QR data must correspond to the certificate record.

The signature/fingerprint data must correspond to the actual signing/verification implementation.

Do not call something "tamper-proof" in a way that implies impossible security guarantees. The implementation should instead provide genuine tamper-evident integrity and verification.

Keep all certificate validation local/offline unless an explicitly separate future online service is added.

---

# 17. CERTIFICATE CENTRE

Provide:

- All Certificates
- Erasure Certificates
- Recovery Certificates
- Search
- Session ID
- Method
- Status
- Date/time
- Duration
- PDF view/open/export
- Pagination/list management

The Certificate Centre should read from real local certificate records.

A generated certificate must become discoverable through the Certificate Centre.

---

# 18. LOCAL DATA / HISTORY

DREX is offline.

Use local storage for:

- operation history;
- certificate metadata;
- dashboard statistics;
- recent activity;
- certificate files;
- relevant audit information.

No cloud database is required.

Do not make core DREX functionality dependent on:

- internet access;
- cloud APIs;
- online authentication;
- online help;
- online method lookup.

---

# 19. HELP CENTER

Help is an internal DREX page.

Do NOT open an external help website.

Do NOT require an internet connection.

Include:

- Getting Started
- Wiping
- Recovery
- Drive Destruction
- Certificates
- Troubleshooting
- Safety
- Operation Logs
- System Status
- relevant support/documentation information

Use the supplied Help UI design.

---

# 20. OFFLINE REQUIREMENT

Normal DREX operation must work with the machine disconnected from the internet.

Verify this during testing.

The installed application must not fail because internet access is unavailable.

Avoid runtime telemetry or cloud dependencies unless explicitly required and made optional; the default product behavior is offline.

---

# 21. HARDWARE/CAPABILITY TRUTH

Device detection and capability assessment must be real.

Do not hard-code:

- device model;
- serial number;
- capacity;
- supported methods;
- health;
- interface.

Use the appropriate Windows/native mechanisms and repository capabilities.

Where a real operation requires administrator privileges, native device access, a particular interface, hardware support, or hardware qualification:

- detect the condition;
- communicate it clearly;
- fail safely;
- do not fake success.

The UI should make the difference between:

`Supported`

`Unsupported`

`Unavailable`

`Requires Privilege`

`Requires Hardware Qualification`

and

`Operation Failed`

clear where relevant.

---

# 22. SAFETY

DREX performs potentially destructive data-sanitization operations.

Implement appropriate safety protections around destructive workflows.

At minimum:

- clear target identification;
- explicit user confirmation;
- method selection;
- capability validation;
- no silent unsafe downgrade;
- accurate logs;
- verification;
- truthful status;
- safe error handling.

Do not expose unsafe physical destruction procedures.

---

# 23. TESTING — DO NOT SKIP THIS

Testing is part of the implementation, not an optional final step.

Run:

### Repository tests

Run the existing tests and regression suite.

### Application tests

Test:

- startup;
- navigation;
- UI states;
- device discovery;
- file/folder selection;
- method selection;
- method routing;
- capability checks;
- operation state transitions;
- error handling;
- cancellation where supported;
- progress;
- logs;
- certificates;
- local storage;
- search;
- PDF generation;
- QR generation;
- certificate verification;
- offline operation.

### Integration tests

Prove:

```text
UI selection
 →
correct method
 →
correct repository implementation
 →
execution
 →
verification
 →
correct result
 →
correct certificate
 →
Certificate Centre
```

Do not only test that buttons change color.

### Hardware testing

Where physical hardware is available, test the actual supported device classes.

At minimum, distinguish:

- HDD/SATA;
- SATA SSD;
- NVMe;
- USB-attached storage;
- unsupported devices.

Use safe test devices.

Do not destroy production/personal data.

### Clean Windows test

Install the generated installer on a clean supported Windows environment.

Verify:

```text
DREX-Setup.exe
 ↓
Installer opens
 ↓
Install completes
 ↓
DREX launches
 ↓
Navigation works
 ↓
Core application starts correctly
 ↓
Required dependencies are present
 ↓
Uninstaller exists
 ↓
Uninstall/reinstall behavior works
```

---

# 24. QUALITY GATE

Do not declare DREX complete merely because:

- the code compiles;
- the UI looks correct;
- unit tests pass;
- a simulated operation passes;
- the installer file exists.

The release is complete only when all applicable gates pass.

## Required gates

### Gate A — Build

Production build succeeds.

### Gate B — Tests

All relevant automated tests pass.

### Gate C — Integration

UI → orchestration → method → verification → certificate flow works.

### Gate D — Offline

Core operation works without internet.

### Gate E — Installer

Inno Setup successfully creates:

`DREX-Setup.exe`

### Gate F — Clean installation

The installer works on a clean supported Windows machine.

### Gate G — Installed application

The installed DREX application launches and operates correctly.

### Gate H — Certificate

Certificates contain real, internally consistent operation information.

### Gate I — Safety

No Destroy Drive physical-destruction workflow exists.

### Gate J — Truthfulness

No successful result is reported unless the actual operation/verification justifies it.

---

# 25. COMMERCIAL-QUALITY HARDENING

Before final release, inspect and address:

- exception handling;
- input validation;
- permissions;
- path handling;
- process execution;
- native-library loading;
- dependency handling;
- temporary files;
- cleanup;
- logging;
- local data integrity;
- certificate integrity;
- installer/uninstaller behavior;
- versioning;
- application metadata;
- icons;
- file associations only if actually needed;
- architecture/bitness consistency;
- Windows compatibility;
- release build reproducibility.

Do not leave development paths, debug switches, fake data, sample credentials, test certificates, or placeholder assets in the production build.

---

# 26. INNO SETUP

Use **Inno Setup** for the final user-facing installer.

Do not introduce WiX, NSIS or MSIX unless a genuine technical blocker makes Inno Setup unsuitable.

The desired installer experience is:

```text
DREX-Setup.exe
      ↓
Welcome to DREX
      ↓
Installation options
      ↓
Choose installation location
      ↓
Install
      ↓
Installing DREX...
      ↓
✓ DREX installed
      ↓
☑ Launch DREX
      ↓
DREX opens
```

The installer must include the complete production application and every dependency required for the installed application to run.

Include required native components.

Do not assume that a development machine's PATH or globally installed runtime is available to the user.

The installer must:

- install application files;
- install required native/runtime dependencies;
- create Start Menu shortcuts;
- optionally create a Desktop shortcut;
- register an uninstaller;
- support clean uninstall;
- support reinstall/upgrade appropriately;
- work offline;
- preserve required local application data according to a deliberate uninstall policy;
- provide version information;
- use the DREX application name and branding;
- allow launch after installation.

---

# 27. WINDOWS INSTALLER VALIDATION

After creating `DREX-Setup.exe`:

1. Verify the installer file exists.
2. Verify its architecture/compatibility.
3. Install on a clean Windows environment.
4. Verify every required file is installed.
5. Verify DREX launches.
6. Verify native components load.
7. Verify core workflows can start.
8. Verify local certificate storage works.
9. Verify the uninstaller exists.
10. Test uninstall.
11. Test reinstall.
12. Test the installed build again.

Do not deliver an installer that only worked from the development directory.

---

# 28. BUILD ARTIFACTS

The final release should produce, at minimum:

```text
DREX-Setup.exe
```

Optionally also produce:

```text
DREX.exe
checksums
release notes
version information
```

Do not hide the final installer inside an obscure temporary directory without clearly identifying it.

---

# 29. VERSIONING

Use a consistent DREX version throughout:

- application UI;
- executable metadata;
- installer;
- certificates where appropriate;
- release information.

Do not leave mismatched development versions.

---

# 30. LOGGING AND ERROR REPORTING

Errors should be useful to the user without exposing unnecessary sensitive information.

For an operation failure:

- identify what failed;
- show the relevant stage;
- provide a safe explanation;
- preserve useful local audit information;
- do not claim success.

For hardware/capability errors:

- explain that the operation is unsupported/unavailable rather than pretending the method ran.

---

# 31. DO NOT BREAK THE EXISTING REPOSITORY

Before modifying repository code:

- inspect it;
- understand dependencies;
- run existing tests;
- identify public interfaces;
- identify native boundaries;
- preserve working functionality.

Refactor only when necessary for integration, correctness, maintainability or production hardening.

If a method is already correct and tested, integrate it instead of rewriting it merely to make the code look different.

---

# 32. UI-TO-METHOD INTEGRATION IS CRITICAL

Every method card shown in the UI must map to a real internal implementation path.

The mapping must be explicit and testable.

Example:

```text
User selects:
ATA Secure Erase
        ↓
DREX method registry
        ↓
ATA Secure Erase adapter
        ↓
Existing DREX ATA implementation
        ↓
Capability check
        ↓
Execution
        ↓
Verification
        ↓
Result
        ↓
Certificate
```

Likewise:

```text
User selects:
CSPRNG Random Overwrite
        ↓
Correct DREX file sanitization implementation
```

and:

```text
User selects:
Quick Recovery
        ↓
Correct DREX recovery implementation
```

There must be no disconnected UI cards.

If an advertised method cannot be implemented honestly from the repository/current environment, do not create a fake implementation. Identify the blocker and make the UI state accurately reflect availability.

---

# 33. SMART SANITIZATION / POLICY ROUTING

Where DREX provides Smart Sanitization or policy-engine behavior:

- inspect actual device capabilities;
- determine applicable methods;
- choose according to the existing DREX policy/implementation;
- clearly communicate the recommendation;
- do not silently perform an unexpected destructive action;
- require the appropriate confirmation before destructive execution.

The UI label should remain simple; implementation complexity belongs inside the core.

---

# 34. METHOD NAMES ARE USER-FACING CONTRACTS

Preserve these exact user-facing names unless a source specification explicitly requires a change.

Drive:

- NIST SP 800-88 Rev.2
- Smart Sanitization
- Device-Native Sanitize
- ATA Secure Erase
- NVMe Secure Erase
- IEEE 2883 Purge
- Verified Overwrite

File/Folder:

- CSPRNG Random Overwrite
- Cryptographic Erasure
- File Slack / Cluster-Tip Sanitization
- Filesystem Metadata Sanitization
- NIST SP 800-88 Policy Engine
- Secure Free-Space Wiping
- Single-Pass Zero Overwrite
- Storage-Aware Sanitization & Fallback
- Temporary / Cache Sanitization

Recovery:

- Quick Recovery
- Smart Recovery
- Targeted Recovery
- Filesystem Recovery
- Deep Recovery
- Fragment Recovery
- Storage / RAID Recovery
- Damaged Media Recovery
- Forensic Recovery

---

# 35. DO NOT ADD UNREQUESTED PRODUCT FEATURES

Do not expand the product into unrelated functionality.

Do not add:

- cloud accounts;
- mandatory login;
- online activation;
- online help;
- unrelated analytics;
- unnecessary social features;
- unnecessary plugins;
- unrelated dashboards;
- physical destruction instructions.

Focus on the supplied DREX scope.

---

# 36. ACCEPTANCE TEST MATRIX

Create an internal test matrix covering at least:

## Navigation

- every sidebar item opens the correct page;
- active page state is correct;
- no dead navigation.

## Dashboard

- statistics reflect real local records;
- devices are real;
- recent activity is real;
- health state is not fabricated.

## Wipe Drive

- all seven methods are displayed;
- only one can be selected;
- each selected method routes correctly;
- unsupported conditions are handled safely;
- progress/logs are real;
- verification is real;
- certificate behavior is correct.

## Wipe File/Folder

- all nine methods are displayed;
- only one can be selected;
- each selected method routes correctly;
- target information is real;
- progress/logs are real;
- certificate behavior is correct.

## Recovery

- all nine methods are displayed;
- only one can be selected;
- recovery log works;
- progress works;
- results are real;
- recovery certificate is correct.

## Destroy Drive

- assessment only;
- no physical destruction;
- capability information is accurate;
- alternative recommendation works;
- no destruction certificate.

## Certificates

- search works;
- categories work;
- PDF opens;
- data matches operation;
- QR data matches certificate;
- signature/fingerprint data is internally consistent;
- failed operations are not falsely certified.

## Help

- all sections work offline.

## Installer

- setup runs;
- install works;
- launch works;
- uninstall works;
- reinstall works.

---

# 37. WHEN YOU ENCOUNTER A BLOCKER

Do not hide blockers.

If you encounter a genuine blocker:

1. determine whether it can be solved within the current project;
2. solve it if reasonably possible;
3. test the solution;
4. only stop if the blocker genuinely prevents a truthful production build.

Never "solve" a blocker by:

- hard-coding success;
- replacing a real operation with a simulation;
- generating fake certificates;
- bypassing safety checks;
- silently removing a method from the UI;
- claiming a hardware operation succeeded when it was not performed.

If the current environment cannot produce/test a Windows `.exe` installer, do not fabricate one. State the exact environment limitation and the exact build step still required.

---

# 38. AUTONOMOUS EXECUTION

Do not repeatedly ask for confirmation for ordinary engineering decisions.

You have permission to:

- inspect the repository;
- inspect all supplied architecture files;
- inspect UI assets;
- create/refactor code;
- install project dependencies when available;
- write tests;
- run tests;
- create build scripts;
- create Inno Setup scripts;
- build the application;
- build the installer;
- run the installer;
- test the installed application;
- fix discovered problems;
- repeat the build/test cycle.

Do not stop after merely producing a plan.

Move from:

```text
Inspect
 →
Implement
 →
Integrate
 →
Test
 →
Fix
 →
Build
 →
Package
 →
Install
 →
Test again
 →
Release
```

---

# 39. TOKEN / TIME DISCIPLINE

Use the available execution budget intelligently.

Do not spend the entire task repeatedly explaining what you intend to do.

Prioritize actual execution:

1. inspect;
2. implement;
3. build;
4. test;
5. fix;
6. package;
7. install;
8. test;
9. deliver.

Avoid unnecessary prose in intermediate output.

---

# 40. FINAL DELIVERY RULE

Do not give the developer a "final" response saying DREX is ready until the final acceptance gates have actually passed.

The final response should clearly provide:

### 1. Installer

`DREX-Setup.exe`

### 2. Application build

`DREX.exe` if appropriate.

### 3. Test result

A concise summary showing which build/integration/installation tests passed.

### 4. Known limitations

Only genuine limitations that remain after testing.

Do not call the product production-ready if a critical acceptance test has failed.

---

# 41. FINAL SUCCESS CONDITION

The objective is:

```text
DREX repository
       +
Architecture package
       +
UI references
       +
This specification
       ↓
       CODEX
       ↓
Complete DREX application
       ↓
Integrated real methods
       ↓
Working UI
       ↓
Verification
       ↓
Certificates
       ↓
Offline operation
       ↓
Automated testing
       ↓
Windows testing
       ↓
Inno Setup
       ↓
DREX-Setup.exe
       ↓
Clean installation
       ↓
Installed DREX tested again
       ↓
FINAL RELEASE
```

The final deliverable is not a source-code-only project.

The final deliverable is not a UI prototype.

The final deliverable is not a simulated demonstration.

The final deliverable is a **working, installable, offline Windows DREX product**, to the extent that all claimed functionality has been genuinely implemented and validated.

---

# 42. FIRST ACTION

Start now.

First:

1. inspect the complete DREX repository;
2. inspect the complete attached `Architecture` package;
3. inspect every UI reference image;
4. inspect the certificate reference;
5. map every UI method to the corresponding repository implementation;
6. identify gaps, duplicates, stubs and hardware-gated components;
7. implement the complete application;
8. build and test;
9. create the Inno Setup installer;
10. install and test the installer on a clean supported Windows environment;
11. fix every discovered issue;
12. repeat until all applicable acceptance gates pass;
13. only then deliver the final `DREX-Setup.exe`.

Do not merely tell me how to do it.

**Do the work.**
