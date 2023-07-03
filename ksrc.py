import logging
from natsort import natsorted
import git
from pathlib import Path, PurePath
import os
import re
import requests
import subprocess
import sys

from config import Config

class GitHelper(Config):
    def __init__(self, bsc, bsc_filter):
        super().__init__(bsc, bsc_filter)

        self.kern_src = os.getenv('KLP_KERNEL_SOURCE', '')
        if self.kern_src and not Path(self.kern_src).is_dir():
            raise ValueError('KLP_KERNEL_SOURCE should point to a directory')

        self.kgr_patches = Path(Path().home(), 'kgr', 'kgraft-patches')
        if not self.kgr_patches.is_dir():
            raise RuntimeError('kgraft-patches does not exists in ~/kgr')

        self.kernel_branches = {
                                'sle12-sp4-ltss' : 'SLE12-SP4-LTSS',
                                'sle12-sp5' : 'SLE12-SP5',
                                'sle15-sp1-ltss' : 'SLE15-SP1-LTSS',
                                'sle15-sp2-ltss' : 'SLE15-SP2-LTSS',
                                'sle15-sp3-ltss' : 'SLE15-SP3-LTSS',
                                'sle15-sp4' : 'SLE15-SP4',
                                'sle15-sp4-rt' : 'SLE15-SP4-RT',
                                'sle15-sp5' : 'SLE15-SP5',
                                'sle15-sp5-rt' : 'SLE15-SP5-RT',
                                '4.12' : 'cve/linux-4.12',
                                '5.3' : 'cve/linux-5.3'
                            }

        # Filter only the branches related to this BSC
        repo = git.Repo(self.kgr_patches).branches
        self.branches = []
        for r in repo:
            if r.name.startswith(self.bsc):
                self.branches.append(r.name)

    def get_cs_branch(self, cs):
        cs_sle, sp, cs_up, rt = self.get_cs_tuple(cs)

        branch_name = ''

        for branch in self.branches:
            # Check if the codestream is a rt one, and if yes, apply the correct
            # separator later on
            if rt and 'rt' not in branch:
                continue

            separator = 'u'
            if rt:
                separator = 'rtu'

            # First check if the branch has more than code stream sharing
            # the same code
            for b in branch.replace(self.bsc + '_', '').split('_'):
                # Only check the branches that are the same type of the branch
                # being searched. Only check RT branches if the codestream is a
                # RT one.
                if rt and 'rtu' not in b:
                    continue
                elif not rt and 'rtu' in b:
                    continue

                sle, u = b.split(separator)
                if f'{cs_sle}.{sp}' != f'{sle}':
                    continue

                # Get codestreams interval
                up = u
                down = u
                if '-' in u:
                    down, up = u.split('-')

                # Codestream between the branch codestream interval
                if cs_up >= int(down) and cs_up <= int(up):
                    branch_name = branch
                    break

                # At this point we found a match for our codestream in
                # codestreams.json, but we may have a more specialized git
                # branch later one, like:
                # bsc1197597_12.4u21-25_15.0u25-28
                # bsc1197597_15.0u25-28
                # Since 15.0 SLE uses a different kgraft-patches branch to
                # be built on. In this case, we continue to loop over the
                # other branches.

        return branch_name

    def format_patches(self, version):
        ver = f'v{version}'
        # index 1 will be the test file
        index = 2

        kgraft_tests_path = Path(Path().home(), 'kgr',
                                      'kgraft-patches_testscripts')
        if not kgraft_tests_path.is_dir():
            raise RuntimeError('Couldn\'t find ~/kgr/kgraft-patches_testscripts')

        # Ensure that a testfile was created before preparing the patches
        test_sh = Path(kgraft_tests_path, f'{self.bsc}_test_script.sh')
        if not test_sh.is_file():
            raise RuntimeError(f'Test file {test_sh} not created.')

        patches_dir = Path(self.bsc_path, 'patches')

        # Filter only the branches related to this BSC
        for branch in self.branches:
            print(branch)
            bname = branch.replace(self.bsc + '_', '')
            bs = ' '.join(bname.split('_'))
            bsc = self.bsc.replace('bsc', 'bsc#')

            prefix = f'PATCH {ver} {bsc} {bs}'

            subprocess.check_output(['/usr/bin/git',
                            '-C', str(self.kgr_patches),
                            'format-patch', '-1', branch,
                            '--start-number', f'{index}',
                            '--subject-prefix', f'{prefix}',
                            '--output-directory', f'{patches_dir}'
                            ])

            index += 1

        subprocess.check_output(['/usr/bin/git',
                        '-C', str(kgraft_tests_path),
                        'format-patch','-1', f'{test_sh}',
                        '--cover-letter',
                        '--start-number', '1',
                        '--subject-prefix', f'PATCH {ver}',
                        '--output-directory', f'{patches_dir}'
                        ])

    def get_commit_subject(commit, savedir=None):
        req = requests.get(f'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit}')
        req.raise_for_status()

        # Save the upstream commit if requested
        if savedir:
            with open(Path(savedir, f'{commit}.patch') , 'w') as f:
                f.write(req.text)

        # Search for Subject until a blank line, since commit messages can be
        # seen in multiple lines.
        return re.search('Subject: (.*?)(?:(\n\n))', req.text,
                         re.DOTALL).group(1).replace('\n', '')

    def get_commits(self, cve):
        if not self.kern_src:
            logging.info('KLP_KERNEL_SOURCE not defined, skip getting SUSE commits')
            return {}

        # do not get the commits twice
        if self.conf.get('commits', ''):
            return self.conf['commits']
        # ensure that the user informed the commits at least once per 'project'
        elif not cve:
            raise RuntimeError(f'No CVE informed or no upstream commits found. Use '
                               '--cve option')

        print('Fetching changes from all supported branches...')

        # Mount the command to fetch all branches for supported codestreams
        args = ['/usr/bin/git', '-C', self.kern_src, 'fetch', 'origin']
        args.extend(self.kernel_branches.values())
        subprocess.check_output(args)

        print('Getting SUSE fixes for upstream commits per CVE branch. It can take some time...')

        commits = { 'upstream' : {} }

        upatches = Path(self.bsc_path, 'upstream')
        upatches.mkdir(exist_ok=True, parents=True)

        # Get backported commits from all possible branches, in order to get
        # different versions of the same backport done in the CVE branches.
        # Since the CVE branch can be some patches "behind" the LTSS branch,
        # it's good to have both backports code at hand by the livepatch author
        for bc, mbranch in self.kernel_branches.items():
            patches = []
            commits[bc] = { 'commits' : [] }

            try:
                patch_files = subprocess.check_output(['/usr/bin/git', '-C',
                            self.kern_src,
                            'grep', '-l', f'CVE-{cve}',
                            f'remotes/origin/{mbranch}'],
                            stderr=subprocess.STDOUT).decode(sys.stdout.encoding)
            except subprocess.CalledProcessError:
                patch_files = ''

            # If we don't find any commits, add a note about it
            if not patch_files:
                continue

            # The command above returns a list of strings in the format
            #   branch:file/path
            for patch in patch_files.splitlines():
                if not patch.endswith('.patch'):
                    continue

                branch_path = Path(self.bsc_path, 'fixes', bc)
                branch_path.mkdir(exist_ok=True, parents=True)

                pfile = subprocess.check_output(['/usr/bin/git', '-C',
                                                self.kern_src,
                                                'show', patch],
                                                stderr=subprocess.STDOUT).decode(sys.stdout.encoding)

                # Split the branch:filepath, and then get the filename only
                _, fname = patch.split(':')
                # removing the patches.suse dir from the filepath
                basename = PurePath(fname).name

                # Save the patch for later review from the livepatch developer
                with open(Path(branch_path, f'{basename}.patch'), 'w') as f:
                    f.write(pfile)

                # Get the upstream commit and save it. The Git-commit can be
                # missing from the patch if the commit is not backporting the
                # upstream fix, and is using a different way to mimic the fix.
                # In this case add a note for the livepatch author to fill the
                # blank when finishing the livepatch
                ups = ''
                m = re.search('Git-commit: ([\w]+)', pfile)
                if m:
                    ups = m.group(1)[:12]
                else:
                    commits['upstream']['Not found'] = 'Not found'

                # Aggregate all upstream fixes found
                if ups and ups not in commits['upstream'].keys():
                    commits['upstream'][ups] = GitHelper.get_commit_subject(ups, upatches)

                # Now get all commits related to that file on that branch,
                # including the "Refresh" ones.
                try:
                    phashes = subprocess.check_output(['/usr/bin/git', '-C',
                                                       self.kern_src,
                                                       'log', '--no-merges',
                                                       '--pretty=oneline',
                                                       f'remotes/origin/{mbranch}',
                                                       '--',
                                                       fname],
                                                      stderr=subprocess.STDOUT).decode('ISO-8859-1')
                except subprocess.CalledProcessError:
                    print(f'File {fname} doesn\'t exists {mbranch}. It could '
                            ' be removed, so the branch is not affected by the issue.')
                    commits[bc]['commits'] = [ 'Not affected' ]
                    continue

                # Skip the Update commits, that only change the References tag
                for hash_entry in phashes.splitlines():
                    if 'Update' in hash_entry and 'patches.suse' in hash_entry:
                        continue

                    hash_commit = hash_entry.split(' ')[0]
                    commits[bc]['commits'].append(hash_commit)

        print('')

        for key, val in commits.items():
            print(f'{key}')
            if key == 'upstream':
                for ups_hash, ups_msg in val.items():
                    print(f'{ups_hash}: "{ups_msg}"')
            else:
                branch_commits = val['commits']
                if not branch_commits:
                    print('None')
                for c in branch_commits:
                    print(c)
            print('')

        return commits

    def get_patched_kernels(self, commits):
        if not commits:
            return []

        if not self.kern_src:
            logging.info('KLP_KERNEL_SOURCE not defined, skip getting SUSE commits')
            return []

        print('Searching for already patched codestreams...')

        patched = []
        for bc, _ in self.kernel_branches.items():
            suse_commits = commits[bc]['commits']
            if not suse_commits:
                continue

            # Grab only the first commit, since they would be put together
            # in a release either way. The order of the array is backards, the
            # first entry will be the last patch found.
            suse_commit = suse_commits[-1]

            tags = subprocess.check_output(['/usr/bin/git', '-C',
                        self.kern_src, 'tag', f'--contains={suse_commit}'])

            for tag in tags.decode().splitlines():
                tag = tag.strip()
                if not tag.startswith('rpm-'):
                    continue

                # Remove noise around the kernel version, like
                # rpm-5.3.18-150200.24.112--sle15-sp2-ltss-updates
                tag = tag.replace('rpm-', '')
                tag = re.sub('--.*', '', tag)

                patched.append(tag)

        # remove duplicates
        return natsorted(list(set(patched)))
