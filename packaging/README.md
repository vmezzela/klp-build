# Packaging klp-build for openSUSE Tumbleweed

This directory contains the files needed to build klp-build as an RPM package
using the [Open Build Service](https://build.opensuse.org) (OBS).

## Files

| File                  | Purpose                                                              |
|-----------------------|----------------------------------------------------------------------|
| `_service`            | OBS source services: clones git, makes tarball, sets spec version    |
| `klp-build.spec`      | RPM spec file                                                        |
| `klp-build.changes`   | RPM changelog (managed with `osc vc`)                                |

## How the `_service` file works

On every `osc commit` (or `osc service runall` locally) OBS runs the three
chained services declared in `_service`:

1. **`obs_scm`** — clones `https://github.com/SUSE/klp-build.git` at the
   configured tag and produces `klp-build-<version>.tar`. The version is
   derived from the tag (e.g. `v1.2.0` -> `1.2.0`).
2. **`set_version`** — rewrites `Version:` in `klp-build.spec` from the
   tarball name.
3. **`recompress`** — gzips the tarball to `klp-build-<version>.tar.gz`.

The spec then derives a PEP 440 string (`pypi_version`) from `%{version}` and
passes it to `setup.py` via the `KLP_BUILD_VERSION` environment variable.

## Cutting a new release

1. Tag the release in git, e.g. `git tag v1.2.1 && git push --tags`.
2. Bump the `<param name="revision">` line in `_service` to the new tag.
3. Add a changelog entry: `osc vc klp-build.changes`.
4. `osc commit -m "klp-build 1.2.1"` — OBS regenerates the tarball and builds.

## Tracking `main` instead of a tag

To package an untagged snapshot, edit `_service`:

```xml
<param name="revision">main</param>
<param name="versionformat">@PARENT_TAG@.post@TAG_OFFSET@.git%h</param>
```

This yields a version like `1.2.0.post279.git8c99c74`. The spec's
`pypi_version` macro converts that to `1.2.0.post279+git8c99c74` for PEP 440.

## Initial OBS package setup

Done once per OBS project:

```bash
osc checkout home:<username>
cd home:<username>
osc mkpac klp-build
cd klp-build

cp /path/to/klp-build/packaging/_service .
cp /path/to/klp-build/packaging/klp-build.spec .
cp /path/to/klp-build/packaging/klp-build.changes .

osc add _service klp-build.spec klp-build.changes
osc commit -m "Initial klp-build package"
```

After the first commit, OBS runs the services, fetches the tarball, and
starts the build.

## Local build (optional)

To test the build locally before submitting:

```bash
osc service runall          # generates the tarball locally
osc build openSUSE_Tumbleweed x86_64
```

## Monitoring and installing

```bash
osc results
osc buildlog openSUSE_Tumbleweed x86_64

sudo zypper addrepo \
    https://download.opensuse.org/repositories/home:<username>/openSUSE_Tumbleweed/ \
    klp-build
sudo zypper refresh
sudo zypper install klp-build
```
