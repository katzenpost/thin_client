# Release and publish procedure

This repository ships three thin clients, each with its own version
and its own git tag:

| Client | Version lives in | Tag | Published by |
|--------|------------------|-----|--------------|
| Python | `pyproject.toml`, `uv.lock`, `debian/changelog` | `py/vX.Y.Z` | [`publish-py.yml`](.github/workflows/publish-py.yml) → PyPI |
| Rust | `Cargo.toml`, `Cargo.lock` | `rust/vX.Y.Z` | [`publish-rust.yml`](.github/workflows/publish-rust.yml) → crates.io |
| Lean | `lakefile.toml` | `lean/vL.M.N` | nothing; consumers pin the tag in their `lakefile.toml` |

The Python and Rust clients are versioned in lockstep (`X.Y.Z`); the
plain `X.Y.Z` tag marks that release at the repository level. The Lean
client has its own version line (`L.M.N`) because it started later and
is fetched by git rev, so it is tagged separately and only bumped when
the Lean sources or the pins in `lake-manifest.json` changed since its
last tag.

Python and Rust are published automatically by GitHub Actions via
trusted publishing (OIDC) when the corresponding tag is pushed. No
credentials are stored anywhere and nothing is ever published from a
developer machine — never run `cargo publish` or `twine` by hand.
Lean has no registry step: `lake` fetches the tagged commit from this
repository, so pushing the tag is the release.

## Release branch

1. Create a release branch off `main`:

   ```bash
   git checkout -b prepare_release_X.Y.Z
   ```

2. Repin katzenpost. The integration test workflow checks out the
   katzenpost commit named by `katzenpost_ref` at the top of the
   `Makefile`, so a release is only tested against that commit. Set it
   to the current `main` of katzenpost:

   ```bash
   git ls-remote https://github.com/katzenpost/katzenpost refs/heads/main
   ```

   and paste the hash into `katzenpost_ref?=` in the `Makefile`.

3. Bump the Python and Rust version to `X.Y.Z`:

   - `version` in `Cargo.toml`
   - `version` in `pyproject.toml`
   - a new top entry in `debian/changelog` (same format as the
     previous entries, `date -R` for the timestamp)
   - the lock files, which record the crate and distribution version
     and must match or the publish fails:

     ```bash
     cargo update --workspace
     uv lock
     ```

     The publish workflow builds with `--locked`; if `Cargo.lock`
     still records the previous crate version, the workflow dies with
     "cannot update the lock file ... because `--locked` was passed".

4. If anything under `ThinClient/`, `ThinClient.lean`, `lakefile.toml`
   or `lake-manifest.json` changed since the last `lean/v*` tag, bump
   `version` in `lakefile.toml` to `L.M.N`.

5. Verify the build exactly the way the publish workflow will:

   ```bash
   cargo build --locked --all-features
   cargo publish --locked --dry-run
   ```

6. Commit, push the branch, open a pull request, and merge it into
   `main` once CI passes. The build job of `publish-rust.yml` runs on
   every pull request, so a stale `Cargo.lock` is caught here while it
   is still a one-line fix on the branch, and the integration workflow
   runs the clients against the freshly pinned katzenpost.

## Tags

7. Tag the merge commit on `main` and push the tags:

   ```bash
   git checkout main && git pull
   git tag X.Y.Z
   git tag py/vX.Y.Z
   git tag rust/vX.Y.Z
   git tag lean/vL.M.N          # only if the Lean version was bumped
   git push origin X.Y.Z py/vX.Y.Z rust/vX.Y.Z lean/vL.M.N
   ```

   The two `py/` and `rust/` tags are what trigger the publish
   workflows; `publish-rust.yml` also runs the namenlos integration
   test before publishing.

8. Watch the two publish workflows in the Actions tab, then confirm
   the new version appears on
   [PyPI](https://pypi.org/project/katzenpost_thinclient/) and
   [crates.io](https://crates.io/crates/katzenpost_thin_client).

If a publish fails after tagging, do not delete, move, or reuse the
tags: released versions are immutable on both registries (PyPI and
crates.io refuse re-uploads of a version number, even after a yank or
deletion), and downstream `lake-manifest.json` files record the commit
behind a `lean/v*` tag. Fix the problem and roll forward to the next
patch version. It is fine for one registry to end up with a version
the other skipped.
