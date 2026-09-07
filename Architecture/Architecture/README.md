# DREX — Codex Architecture Brief

## Goal
Build DREX as a complete, fully offline Windows desktop application using the existing DREX GitHub repository for its methods and the supplied UI images as the visual reference.

## Inputs
- **GitHub:** existing DREX sanitization/recovery implementations and tests.
- **UI DESIGN:** approved visual reference images in this folder.
- **This vault:** page behavior and product rules.

## Final output
- Production-ready DREX application.
- Windows installer: **`DREX-Setup.exe`** using **Inno Setup**.
- Installed application must run offline.

## Responsibility
The developer defines **what, where and when**. Codex decides the technical architecture, code structure, framework, state management, integration, testing and build details.

## Non-negotiable rules
1. Preserve the supplied DREX UI/UX direction.
2. Reuse and integrate existing repository methods; do not duplicate working methods unnecessarily.
3. One user-facing tile per method listed in the page specifications.
4. One method can be selected at a time on Wipe Drive, Wipe File/Folder and Recovery.
5. Do not claim certification merely because a method follows a standard.
6. DREX must not require internet access for normal operation.
7. **Destroy Drive is informational only. It does not physically destroy a drive.**
8. Help is the built-in offline Help Center; do not depend on an external website.
9. Do not create a successful certificate for a failed or unverified operation.
10. Test the installed build, not only the development build.


## Certificate
The `Certificate/` folder contains the supplied certificate reference and the executable certificate-generation specification for Codex.
