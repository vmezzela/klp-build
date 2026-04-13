# Packaging klp-build for openSUSE Tumbleweed

This directory contains the files needed to build klp-build as an RPM package
using the [Open Build Service](https://build.opensuse.org) (OBS).

## Version Format

The spec uses two version macros to satisfy both RPM and Python (PEP 440)
version requirements:

| Macro | Format | Example | Used by |
|-------|--------|---------|---------|
| `rpm_version` | Dots only | `1.2.0.post246.git2cf39e3` | RPM package name, tarball |
| `pypi_version` | PEP 440 with local label | `1.2.0.post246+git2cf39e3` | Python setuptools |

The version is passed to `setup.py` via the `KLP_BUILD_VERSION` environment
variable. When this variable is not set (e.g. during development),
`setuptools-git-versioning` derives the version from git tags automatically.

## Step-by-Step Build Instructions

### 1. Generate the source tarball

NOTE: I am not sure this is needed at all, when we start packaging klp-build,
we could just use the release number.

From the root of the klp-build git repository:

```bash
COMMIT=$(git log -1 --format='%h')
COUNT=$(git rev-list --count v1.2.0..HEAD)
VERSION="1.2.0.post${COUNT}.git${COMMIT}"

git archive --format=tar.gz \
    --prefix="klp-build-${VERSION}/" \
    -o "klp-build-${VERSION}.tar.gz" \
    HEAD
```

### 2. Update the spec version

Edit `packaging/klp-build.spec` and update the two version macros at the top:

```spec
%define rpm_version  1.2.0.post<COUNT>.git<COMMIT>
%define pypi_version 1.2.0.post<COUNT>+git<COMMIT>
```

### 3. Update the changelog

```bash
cd packaging
osc vc klp-build.changes
```

### 4. Create the OBS package

```bash
osc checkout home:<username>
cd home:<username>
osc mkpac klp-build
cd klp-build
```

### 5. Copy files into the OBS package

```bash
cp /path/to/klp-build/packaging/klp-build.spec .
cp /path/to/klp-build/packaging/klp-build.changes .
cp /path/to/klp-build/klp-build-<VERSION>.tar.gz .
```

### 7. Submit to OBS

```bash
osc addremove
osc commit -m "klp-build <VERSION>"
```

### 8. Monitor the build

```bash
osc results
osc buildlog openSUSE_Tumbleweed x86_64
```

### 9. Local build (optional)

To test the build locally before submitting:

```bash
osc build openSUSE_Tumbleweed x86_64
```

### 10. Install from your repo

Once the build succeeds:

```bash
sudo zypper addrepo \
    https://download.opensuse.org/repositories/home:<username>/openSUSE_Tumbleweed/ \
    klp-build
sudo zypper refresh
sudo zypper install klp-build
```
