# Release and publish procedure

Both packages are published automatically by GitHub Actions via
trusted publishing (OIDC) when the corresponding tag is pushed:
`py/v<version>` triggers
[`publish-py.yml`](.github/workflows/publish-py.yml) (PyPI) and
`rust/v<version>` triggers
[`publish-rust.yml`](.github/workflows/publish-rust.yml) (crates.io).
No credentials are stored anywhere and nothing is ever published
from a developer machine — never run `cargo publish` or `twine`
by hand.

The Rust and Python packages are versioned in lockstep. To release
version `X.Y.Z`:

1. Create a release branch off `main`:

   ```bash
   git checkout -b prepare_release_X.Y.Z
   ```

2. Bump `version` in **both** `Cargo.toml` and `pyproject.toml`
   to `X.Y.Z`.

3. Regenerate the lock file entry for the crate — easy to forget,
   and the publish fails without it:

   ```bash
   cargo update --workspace
   ```

   The publish workflow builds with `--locked`; if `Cargo.lock`
   still records the previous crate version, the workflow dies with
   "cannot update the lock file ... because `--locked` was passed".

4. Verify the build exactly the way the publish workflow will:

   ```bash
   cargo build --locked --all-features
   ```

5. Commit, push the branch, open a pull request, and merge it into
   `main` once CI passes. The build job of `publish-rust.yml` runs
   on every pull request, so a stale `Cargo.lock` is caught here,
   while it is still a one-line fix on the branch.

6. Tag the merge commit on `main` with all three tags and push them:

   ```bash
   git checkout main && git pull
   git tag X.Y.Z
   git tag py/vX.Y.Z
   git tag rust/vX.Y.Z
   git push origin X.Y.Z py/vX.Y.Z rust/vX.Y.Z
   ```

   The plain `X.Y.Z` tag is a repo-level release marker; the two
   prefixed tags are what trigger the publish workflows.

7. Watch the two publish workflows in the Actions tab, then confirm
   the new version appears on
   [PyPI](https://pypi.org/project/katzenpost_thinclient/) and
   [crates.io](https://crates.io/crates/katzenpost_thin_client).

If a publish fails after tagging, do not delete, move, or reuse the
tags: released versions are immutable on both registries (PyPI and
crates.io refuse re-uploads of a version number, even after a yank
or deletion). Fix the problem and roll forward to the next patch
version. It is fine for one registry to end up with a version the
other skipped.
