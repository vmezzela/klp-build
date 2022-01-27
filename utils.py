import json
import pathlib
import os
import re
import requests

class Setup:
    _cs = {}
    _cs_file = None

    def __init__(self, destination, redownload, bsc, cve, conf,
                file_funcs, mod):
        # Prefer the argument over the environment
        if not destination:
            destination = pathlib.Path(os.getenv('KLP_ENV_DIR'))
            if not destination:
                raise ValueError('--dest or KLP_ENV_DIR should be defined')

        self._env = pathlib.Path(destination)
        self._work = pathlib.Path(os.getenv('KLP_WORK_DIR'))

        self._bsc = bsc
        self._bsc_path = pathlib.Path(self._work, bsc)
        if self._bsc_path.exists() and not self._bsc_path.is_dir():
            raise ValueError('--bsc needs to be a directory, or not to exist')

        self._cve = cve
        self._conf = conf
        self._file_funcs = file_funcs
        # FIXME: currently run-ccp.sh only accepts one file + multiple
        # functions, so grab the first file-func argument as use to create the
        # setup.sh file
        # file_funcs has the content like
        # [ ['fs/file.c', 'func1', 'func2'], ['fs/open.c', 'func3', 'func4']
        # Get the file from the first file-func argument
        self._src = file_funcs[0][0]
        # Return the files from the first file-func argument
        self._funcs = file_funcs[0][1:]
        self._mod = mod

        if not self._env.is_dir():
            raise ValueError('Destiny should be a directory')

        self._redownload = redownload

        self._rpm_dir = pathlib.Path(self._env, 'kernel-rpms')
        self._ex_dir = pathlib.Path(self._env, 'ex-kernels')
        self._ipa_dir = pathlib.Path(self._env, 'ipa-clones')

    def get_rename_prefix(self, cs):
        if 'SLE12-SP3' in cs:
            return 'kgr'
        return 'klp'

    def find_cs_file(self, err=False):
        # If _cs_file is populated, so is _codestreams
        if self._cs_file:
                return

        # If KLP_CS_FILE env var is populated, is must be a valid file
        self._cs_file = os.getenv('KLP_CS_FILE')
        if self._cs_file and not os.path.isfile(self._cs_file):
            raise ValueError(self._cs_file + ' is not a valid file!')

        if not self._cs_file:
            self._cs_file = pathlib.Path(self._bsc_path, 'codestreams.in')

        # If err is true, return error instead of only populare cs_file member
        if err and not self._cs_file.is_file():
            raise ValueError('Couldn\'t find codestreams.in file')

    def download_codestream_file(self):
        self.find_cs_file()

        if os.path.isfile(self._cs_file) and not self._redownload:
            print('Found codestreams.in file, skipping download.')
            return
        elif not self._cs_file:
            self._cs_file = pathlib.Path(self._bsc_path, 'codestreams.in')

        print('Downloading the codestreams.in file into ' + str(self._cs_file))
        req = requests.get('https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv')

        # exit on error
        req.raise_for_status()

        first_line = True
        with open(self._cs_file, 'w') as f:
            for line in req.iter_lines():
                # skip empty lines
                if not line:
                    continue

                # skip file header
                if first_line:
                    first_line = False
                    continue

                # remove the last two columns, which are dates of the line
                # and add a fifth field with the forth one + rpm- prefix, and
                # remove the micro version number
                columns = line.decode('utf-8').split(',')
                rpm_name = 'rpm-' + re.sub('\.\d+$', '', columns[2])

                f.write(columns[0] + ',' + columns[1] + ',' + columns[2] + ',,' + rpm_name + '\n')

    def write_setup_script(self, cs, dest):
        cs_dir = pathlib.Path(dest, cs, 'x86_64')
        cs_dir.mkdir(parents=True, exist_ok=True)

        setup = pathlib.Path(cs_dir, 'setup.sh')

        # Create a work_{file}.c structure to be used in run-ccp.sh
        work_dir = 'work_' + pathlib.Path(self._src).name
        work_path = pathlib.Path(setup.with_name(work_dir))
        work_path.mkdir(parents=True, exist_ok=True)

        src = pathlib.Path(self._ex_dir, cs, 'usr', 'src')
        sdir = pathlib.Path(src, self._cs[cs]['kernel'])
        odir = pathlib.Path(src, self._cs[cs]['kernel'] + '-obj', 'x86_64',
                                'default')
        symvers = pathlib.Path(odir, 'Module.symvers')

        obj = pathlib.Path(self._ex_dir, cs, 'x86_64', 'boot', 'vmlinux-' +
                self._cs[cs]['kernel'].replace('linux-', '') + '-default')

        ipa = pathlib.Path(self._ipa_dir, cs, 'x86_64', self._src + '.000i.ipa-clones')

        # TODO: currently run-ccp.sh only handles one file + functions, so pick
        # the first one in this case
        with setup.open('w') as f:
            f.write('export KCP_FUNC={}\n'.format(','.join(self._funcs)))
            f.write('export KCP_PATCHED_SRC={}\n'.format(self._src))
            f.write('export KCP_DEST={}\n'.format(str(dest)))
            # FIXME: check which readelf to use
            f.write('export KCP_READELF={}\n'.format('readelf'))
            f.write('export KCP_RENAME_PREFIX={}\n'.format(self.get_rename_prefix(cs)))
            f.write('export KCP_WORK_DIR={}\n'.format(work_path))
            f.write('export KCP_KBUILD_SDIR={}\n'.format(sdir))
            f.write('export KCP_KBUILD_ODIR={}\n'.format(odir))
            f.write('export KCP_MOD_SYMVERS={}\n'.format(symvers))
            # FIXME: change fixes vmlinux to module when it fits
            f.write('export KCP_PATCHED_OBJ={}\n'.format(obj))
            f.write('export KCP_IPA_CLONES_DUMP={}\n'.format(ipa))

    def prepare_bsc_dirs(self):
        self.find_cs_file(err=True)

        if not self._ex_dir.is_dir() or not self._ipa_dir.is_dir():
            print(self._ex_dir, self._ipa_dir)
            raise RuntimeError('KLP_ENV_DIR was not defined, or ex-kernel/ipa-clones does not exist')

        # Create the necessary directories for each codestream and populate the
        # setup.sh script
        for cs in self._cs.keys():
            dest = pathlib.Path(self._bsc_path, 'c')
            dest.mkdir(parents=True, exist_ok=True)

            self.write_setup_script(cs, dest)

    def write_conf_json(self):
        files = {}
        for f in self._file_funcs:
            filepath = f[0]
            funcs = f[1:]
            files[filepath] = funcs
        data = { 'bsc' : self._bsc,
                'cve' : self._cve,
                'conf' : self._conf,
                'mod' : self._mod,
                'files' : files }
        with open(pathlib.Path(self._bsc_path, 'conf.json'), 'w') as f:
            f.write(json.dumps(data, indent=4))

    def download_env(self):
        print('FIXME: implement the download and extraction of kernel rpms and ipa-clones')

    def prepare_env(self):
        self._bsc_path.mkdir(exist_ok=True)

        self.write_conf_json()

        self.download_codestream_file()

        with self._cs_file.open() as cs_file:
            for line in cs_file:
                cs, target, _, _, kernel = line.strip().split(',')
                self._cs[cs] = { 'target' : target, 'kernel' : kernel.replace('rpm', 'linux') }

        self.prepare_bsc_dirs()
