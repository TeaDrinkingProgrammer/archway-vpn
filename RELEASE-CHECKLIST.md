# Release checklist

1. Make sure `main` is green: the ci and deny workflows passed on the last commit.
2. On a branch, set the new version:
   - `version` in `Cargo.toml`, then run `cargo check` so `Cargo.lock` follows.
   <!-- AUR package not published yet
   - `pkgver` in `packaging/aur/PKGBUILD` (the version without the `v`), and reset `pkgrel` to 1.
   -->
3. Run the kernel tests locally: `./scripts/netns-test.sh`.
4. Open a pull request, wait for CI, and merge it.
5. In GitHub, go to Releases > Draft a new release:
   - Create a new tag on `main`: the version with a `v` in front, e.g. `v0.3.0`. It must match `Cargo.toml`.
   - Click Generate release notes, check them, and publish.

   Publishing starts the release workflow: it checks the tag, builds the `.deb` and `.rpm`, attests them and adds
   them to the release. That takes a few minutes, so the release is briefly without packages.
6. Check the release once the workflow is done:
   - It has the `.deb`, the `.rpm` and `SHA256SUMS`.
   - The attestation verifies: `gh attestation verify archway-vpn_*.deb -R TeaDrinkingProgrammer/archway-vpn`.
   - The package installs and connects on Fedora and Ubuntu.
<!-- AUR package not published yet
7. Update the AUR package with the new `PKGBUILD` (and `.SRCINFO`: `makepkg --printsrcinfo > .SRCINFO`).
-->

If the release workflow fails, fix the cause on `main`, delete the release and its tag, and publish it again from
step 5:

```bash
gh release delete v0.3.0 --cleanup-tag --yes
```
