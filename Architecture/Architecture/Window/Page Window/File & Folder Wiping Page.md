# Wipe File/Folder

Purpose: sanitize selected files/folders.

Show file/folder properties and these 9 methods:
1. CSPRNG Random Overwrite — Replace sensitive files with unpredictable data.
2. Cryptographic Erasure — Make protected data permanently inaccessible.
3. File Slack / Cluster-Tip Sanitization — Clear hidden remnants around files.
4. Filesystem Metadata Sanitization — Remove exposed filesystem traces.
5. NIST SP 800-88 Policy Engine — Choose a policy-backed sanitization strategy.
6. Secure Free-Space Wiping — Clear recoverable traces from unused space.
7. Single-Pass Zero Overwrite — Clean selected files with verified zero overwrite.
8. Storage-Aware Sanitization & Fallback — Choose the safest available path.
9. Temporary / Cache Sanitization — Clear temporary files and residual traces.

Only one method can be selected.

Integrate existing repository code. If multiple repository layers implement filesystem metadata sanitization, expose one user-facing capability.

Start → validate target/method → execute → live log/progress → verify where applicable → certificate on truthful successful completion.
