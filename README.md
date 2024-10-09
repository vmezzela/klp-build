# klp-build

The kernel livepatching creation tool

## Development

To install the project and dependencies use:

`pipx install .`

To run the project locally and test your changes use:

`./klp-build`

To run tests use:

`tox -e tests`

## Configuration
klp-build supports a per-user configuration file located in
__~/.config/klp-build/config__, following the standard ``key=value`` format.
The mandatory variables are:

#### work_dir
Path to directory where the livepatch data/code will be placed, including the one
generated by the different stages of the livepatch creation.
By default set to: __~/klp/livepatches__.

#### data_dir
Path to directory where the dowloaded kernels source code will be placed. To create a
livepatch for upstream kernel, it has to point to a kernel tree with the
sources already built. By default set to: __~/klp/data__.
Option ``--data-dir``, if set, will overwrite the path specified here.

# Creating a livepatch for upstream kernels - Not production ready yet

The current approach to create for upstream kernels needs a directory with the
source code, and the compiled sources in the same location.


## Setup

```sh
klp-build setup --data-dir /home/mpdesouza/git/linux \
                --name sound_lp \
                --mod snd-pcm \
                --conf CONFIG_SND_PCM \
                --file-funcs sound/core/pcm.c snd_pcm_attach_substream
```

This command creates a new directory ~/klp/livepatches/sound_lp. The setup phase
checks if the configuration entry is set, and if the symbol being extracted is
present in the module.

Explaining some arguments:
--mod: The module to be livepatched. If empty, vmlinux will be livepatched
       instead.
--file-funcs: Lists the symbols (hence funcs) from each file. These
              symbols will be extracted into the livepatching.


## Extraction

For upstream kernels we only support using [clang-extract](https://github.com/SUSE/clang-extract)
for code extraction:
```sh
klp-build extract --name sound_lp
```

The contents of the generated file are placed
on ~/klp/livepatches/sound_lp/ce/__$codestream__/lp.


__IMPORTANT__: Do not use it on production. klp-build is still only used to
create livepatches on SLE kernels using klp-ccp. The tool needs more tests in
order to rely on this process to create livepatches for upstream kernels. More
work needs to be done before it happens, like:

* Generate a template to include and generate a compilable livepatch
* Simplify the setup/extraction in just one pass in order to make it even easier
  for the livepatch developer.
* Many other small adjustments


# Creating a livepatch for multiple SUSE Linux Enterprise codestreams


## Configuration

Along with the variables mentioned earlier, we also need:

#### kernel_src_dir
Only used for SLE kernels. Should contain the path to the
[kernel-source tree](https://github.com/SUSE/kernel-source) in order to check
which codestreams already contains the fix and don't need the livepatch. It also
gets the fix for the CVE being livepatched.

## Setup
To create a new "livepatch project", use the setup command:

```sh
klp-build setup --name bsc1197597 --cve 2022-1048 --mod snd-pcm --conf CONFIG_SND_PCM --file-funcs sound/core/pcm.c snd_pcm_attach_substream snd_pcm_detach_substream --codestreams '15.5' --archs x86_64 ppc64le
```

klp-build will check if the configuration is enabled, if the symbol is present
on the module being livepatched. The check will be done in all architectures
informed as argument. If the argument is not informed, it will return an error
if configuration is not available on any of them.


## Extraction

At this point we support two different backends to perform the code extraction:
[klp-ccp](https://github.com/SUSE/klp-ccp) and
[clang-extract](https://github.com/SUSE/clang-extract), but only klp-ccp is
being used in production. To extract the livepatches, run the command below:

```sh
klp-build extract --name bsc1197597 --type ccp
```

Depending of the __type__ chosen, it will use klp-ccp or clang-extract to
extract the livepatch from the sources. The resulting livepatched will be placed
on __~/klp/livepatches/bsc1197597/ccp/$codestream__/lp, for example:

``/home/john/klp/livepatches/bsc1197597/ccp/15.5u40/lp``
