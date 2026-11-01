# Releasing REVOC

How a REVOC release goes out: GitHub repo + release, container images on GHCR,
Helm chart, `revoc-sdk` on PyPI, `@revoc-io/sdk` on npm, and the docs site on
<https://revoc.io>. Everything except the one-time setup below is driven by
`.github/workflows/release.yml` (on a `vX.Y.Z` tag) and `.github/workflows/docs.yml`
(on every push to `main`).

## One-time setup

### 1. GitHub organization and repository

1. Repository `revoc-ai/revoc` → **Settings → General**: set the description,
   website `https://revoc.io` and topics. Leave visibility private until the
   first push has been reviewed, then switch to **Public**.
2. **Settings → Teams**: create the `revoc-ai/maintainers` team used by `CODEOWNERS`.
3. **Settings → Branches**: protect `main` — require a PR, required checks from
   `ci.yml` and `security.yml`, and no force pushes.
4. **Settings → Code security**: enable secret scanning, push protection,
   Dependabot alerts and **private vulnerability reporting** — `SECURITY.md`
   relies on it as the only security channel.
5. **Settings → Moderation options → Reported content**: allow content reports
   to be sent to repository admins — `CODE_OF_CONDUCT.md` relies on it.
6. **Settings → Actions → General**: workflow permissions "Read repository
   contents"; the workflows request anything more per job.
7. **Settings → Packages**: after the first image push, set
   `ghcr.io/revoc-ai/revoc` to **Public**.
8. **Settings → General → Features**: enable **Discussions** (used for questions
   and enterprise enquiries).

### 2. PyPI (`revoc-sdk`) — trusted publishing, no token

1. Sign in at <https://pypi.org> with 2FA enabled, and check the name is free.
2. **Account → Publishing → Add a new pending publisher**:
   - PyPI project name: `revoc-sdk`
   - Owner: `revoc-ai` · Repository: `revoc` · Workflow: `release.yml`
   - Environment: `pypi`
3. In GitHub, **Settings → Environments → New environment** `pypi` (optionally
   require a reviewer).

The first tagged release creates the project; later releases reuse the publisher.

### 3. npm (`@revoc-io/sdk`)

1. Create the npm organization **`revoc-io`** at <https://www.npmjs.com> (2FA on).
2. The first publish needs a token, because a trusted publisher can only be attached
   to a package that already exists:
   - Create a **granular access token** with read/write on the `@revoc-io` scope
     and a short expiry.
   - In GitHub, create environment **`npm`** and add the secret `NPM_TOKEN` to it.
3. After the first release: on npmjs.com, open `@revoc-io/sdk` → **Settings →
   Trusted publisher → GitHub Actions** (`revoc-ai/revoc`, `release.yml`,
   environment `npm`). Then delete the `NPM_TOKEN` secret and revoke the token.
   The workflow already sets `id-token: write` and `--provenance`.

### 4. Docs on revoc.io (GitHub Pages)

1. **Settings → Pages → Build and deployment → Source: GitHub Actions.**
2. **Settings → Pages → Custom domain:** `revoc.io` → Save, then tick
   **Enforce HTTPS** once the certificate is issued (can take up to an hour).
3. At your DNS registrar for `revoc.io`:
   - Apex `revoc.io`: four `A` records → `185.199.108.153`, `185.199.109.153`,
     `185.199.110.153`, `185.199.111.153` (and optionally `AAAA` →
     `2606:50c0:8000::153`, `2606:50c0:8001::153`, `2606:50c0:8002::153`, `2606:50c0:8003::153`).
   - `www.revoc.io`: `CNAME` → `revoc-ai.github.io`.
4. Recommended: **Organization settings → Pages → Add a verified domain** for
   `revoc.io` (a TXT record), which stops anyone else claiming it on GitHub Pages.
5. Run the **Docs** workflow manually (Actions → Docs → Run workflow) or push to `main`.

The repo publishes no email addresses: security reports, conduct reports and
questions all go through GitHub features enabled in step 1.

## Each release

1. Bump versions together:
   - `Cargo.toml` workspace crates, `sdk/python/pyproject.toml`,
     `sdk/node/package.json`, `admin-api/pyproject.toml`, `helm/revoc/Chart.yaml`
     (`version` and `appVersion`), `[telemetry].service_version` in `configs/revoc.toml`.
2. Update `CHANGELOG.md` (`git cliff --unreleased` gives a draft).
3. Run the checks locally: `make lint test`, `cargo audit`, `cargo deny check`, the
   admin-api and SDK test suites, and `mkdocs build --strict -f docs/mkdocs.yml`.
4. Open a PR, get it green and merged.
5. Tag from `main` and push the tag:

   ```bash
   git tag -s v0.1.0-beta.1 -m "REVOC v0.1.0-beta.1"
   git push origin v0.1.0-beta.1
   ```

6. Watch **Actions → Release**: tests → binaries → GHCR images → Helm chart →
   PyPI → npm → GitHub release. If a publish step fails, fix it and re-run just
   that job; PyPI and npm both reject re-uploading a version that already exists.
7. Check that it all landed:

   ```bash
   pip install --pre revoc-sdk==0.1.0b1
   npm view @revoc-io/sdk@beta version
   docker pull ghcr.io/revoc-ai/revoc:0.1.0-beta.1
   curl -sI https://revoc.io | head -1
   ```
