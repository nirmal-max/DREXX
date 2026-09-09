# Deploying the console

The console is **one static HTML file**. No build step, no framework, no server, no
dependencies to install. That is a deliberate property, not a shortcut: on hackathon day
the fewest moving parts wins.

---

## First, the question everyone asks: where is the API?

**There isn't one, and there should not be one.**

The console does not ask a backend whether a chain is valid. It re-implements the
length-prefixed encoding and SHA-256 **in the browser** and recomputes every entry hash
itself. That is strictly stronger than a `/verify` endpoint, because a verification
endpoint asks you to trust the server that produced the answer.

> A judge asking "how do I know the page isn't just printing green?" can open DevTools and
> watch `crypto.subtle.digest` run. That is not available to a tool whose verdict arrives
> as JSON from someone else's server.

So the deployment is static hosting, and the "API" is the file format. If you later want
the page to load a chain from elsewhere instead of the embedded one, that is a `fetch()`
of a `chain.json`, still no server logic.

**What must never be deployed:** the CLI and the witness node. The CLI writes to raw block
devices; the witness holds a signing key. Neither belongs on the public internet. See
`../HOSTING.md`.

---

## Option 1, Vercel (a public URL)

### Via the dashboard, no CLI

1. Push this `console-app/` folder to a GitHub repository.
2. **vercel.com** → *Add New* → *Project* → import that repo.
3. Framework Preset: **Other**. Build Command: **leave empty**. Output Directory: **leave
   empty** (or `.`).
4. **Deploy.**

There is nothing to configure because there is nothing to build.

### Via the CLI

```bash
npm i -g vercel
cd console-app
vercel            # preview deployment
vercel --prod     # production URL
```

`vercel.json` ships alongside and sets a strict Content-Security-Policy, `nosniff`,
and a `Permissions-Policy` denying camera, microphone, geolocation and USB. A forensics
tool asking for none of those is a detail worth having in place if anyone inspects
headers.

---

## Option 2, GitHub Pages

```bash
git subtree push --prefix console-app origin gh-pages
```

Or in repo **Settings → Pages**, set the source to `/console-app` on `main`.

Note: GitHub Pages ignores `vercel.json`, so the CSP header does not apply there. The page
is still safe, it loads no third-party scripts, but Vercel gives the stronger posture.

---

## Option 3, local, and this is what to use on demo day

```bash
cd console-app
python -m http.server 8080     # http://localhost:8080
```

It also opens directly as a `file://`, the data is embedded, so no server is required at
all.

**Use this for judging.** A hosted URL adds a dependency on venue Wi-Fi for no benefit,
and venue Wi-Fi is the single most reliable thing to fail during a demo. Keep the Vercel
link as the thing you *share afterwards*, not the thing you *present from*.

---

## Testing before you show it

| Check | Expected |
|---|---|
| Page loads, status bar reads **verified** | green lamp, chain `1d33c5ee78fbc0c1`, 3 entries |
| **Ledger**, click any row | expands to the signed fields |
| **Integrity** → *Alter selected entry* | turns red, names the sequence, log records it |
| **Integrity** → *Restore original* | returns to green |
| **Certificate** | clause references render in brass under each field |
| **Evidence** | four files, original and carved SHA-256 identical |
| Resize to phone width | left rail becomes a scrolling top bar; tables scroll inside their own containers |
| Dark mode | switch OS theme, the whole palette follows |

The Integrity view is the demo. Everything else is context for it.

---

## Updating the data it shows

The chain, certificate values and proof hashes are embedded near the bottom of
`index.html` in `const CHAIN`, and `const PROOF`. To show a fresh run:

```bash
cd ../akhanda
python scripts/demo_bundle.py --witness http://<witness-ip>:8000
```

Then copy `demo_bundle/chain.json` into the `CHAIN` constant and the values from
`byte_identical_proof.json` into `PROOF`. Both are plain JSON, no transformation needed.

Keep them real. The one thing that would genuinely damage this project in front of a judge
is a hash on screen that does not match the file it claims to describe.
