import concurrent.futures
import errno
from lxml import etree
from pathlib import Path
import os
from osctiny import Osc
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

class IBS:
    def __init__(self, cfg):
        self.cfg = cfg
        self.osc = Osc(url='https://api.suse.de')

        self.ibs_user = re.search('(\w+)@', cfg.email).group(1)
        self.prj_prefix = 'home:{}:klp'.format(self.ibs_user)

        self.arch = 'x86_64'

        self.cs_data = {
                'kernel-default' : '(kernel-default\-(extra|(livepatch-devel|kgraft)?\-?devel)?\-?[\d\.\-]+.x86_64.rpm)',
                'kernel-source' : '(kernel-(source|macros|devel)\-?[\d\.\-]+.noarch.rpm)'
        }

    def do_work(self, func, args, workers=0):
        if len(args) == 0:
            return

        if workers == 0:
            workers = os.cpu_count()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            results = executor.map(func, args)
            for result in results:
                if result:
                    print(result)

    # The projects has different format: 12_5u5 instead of 12.5u5
    def get_projects(self):
        return self.osc.search.project("starts-with(@name, '{}')".format(self.prj_prefix))

    def get_project_names(self):
        names = []
        for result in self.get_projects().findall('project'):
            names.append(result.get('name'))

        return names

    def delete_project(self, prj, verbose=True):
        if not self.osc.projects.exists(prj):
            return

        ret = self.osc.projects.delete(prj)
        if type(ret) is not bool:
            print(etree.tostring(ret))
            raise ValueError(prj)

        if verbose:
            print('\t' + prj)

    def extract_rpms(self, args):
        cs, rpm, dest = args

        fcs = self.cfg.codestreams[cs]['cs']
        kernel = self.cfg.codestreams[cs]['kernel']

        if 'livepatch' in rpm or 'kgraft-devel' in rpm:
            path_dest = Path(self.cfg.ipa_dir, fcs, self.arch)
        elif re.search('kernel\-default\-\d+', rpm) or \
                re.search('kernel\-default\-devel\-\d+', rpm):
            path_dest = Path(self.cfg.ex_dir, fcs, self.arch)
        else:
            path_dest = Path(self.cfg.ex_dir, fcs)

        fdest = Path(dest, rpm)
        path_dest.mkdir(exist_ok=True, parents=True)

        cmd = 'rpm2cpio {} | cpio --quiet -idm'.format(str(fdest))
        subprocess.check_output(cmd, shell=True, cwd=path_dest)

        # Move ipa-clone files to path_dest
        if 'livepatch' in rpm or 'kgraft-devel' in rpm:
            src_dir = Path(path_dest, 'usr', 'src',
                                    'linux-{}-obj'.format(kernel),
                                  self.arch, 'default')

            for f in os.listdir(src_dir):
                shutil.move(Path(src_dir, f), path_dest)

            # remove leftovers
            os.remove(Path(path_dest, 'Symbols.list'))
            shutil.rmtree(Path(path_dest, 'usr'))

        print('Extracting {} {}: ok'.format(cs, rpm))

    def download_and_extract(self, args):
        cs, prj, repo, arch, pkg, rpm, dest = args

        self.download_binary_rpms(args)

        # Do not extract kernel-macros rpm
        if 'kernel-macros' not in rpm:
            self.extract_rpms( (cs, rpm, dest) )

    def download_cs_data(self, cs_list):
        rpms = []
        extract = []

        print('Getting list of files...')
        for cs in cs_list:
            jcs = self.cfg.codestreams[cs]
            prj = jcs['project']
            repo = jcs['repo']

            path_dest = Path(self.cfg.kernel_rpms, jcs['cs'])
            path_dest.mkdir(exist_ok=True)

            for k, regex in self.cs_data.items():
                if repo == 'standard':
                    pkg = k
                else:
                    pkg = '{}.{}'.format(k, repo)

                # arch is fixed for now
                ret = self.osc.build.get_binary_list(prj, repo, self.arch, pkg)
                for file in re.findall(regex, str(etree.tostring(ret))):
                    rpm = file[0]
                    rpms.append( (cs, prj, repo, self.arch, pkg, rpm, path_dest) )

                    # Do not extract kernel-macros rpm
                    if 'kernel-macros' not in rpm:
                        extract.append( (cs, rpm, path_dest) )

        print('Downloading {} rpms...'.format(len(rpms)))
        self.do_work(self.download_and_extract, rpms)

    def download_binary_rpms(self, args):
        cs, prj, repo, arch, pkg, rpm, dest = args

        try:
            self.osc.build.download_binary(prj, repo, arch, pkg, rpm, dest)
            print('{} {}: ok'.format(cs, rpm))
        except OSError as e:
            if e.errno == errno.EEXIST:
                print('{} {}: already downloaded. skipping.'.format(cs, rpm))
            else:
                raise RuntimeError('download error on {}: {}'.format(prj, rpm))

    def apply_filter(self, item_list):
        if not self.cfg.filter:
            return item_list

        filtered = []
        for item in item_list:
            if not re.match(self.cfg.filter, item.replace('_', '.')):
                continue

            filtered.append(item)

        return filtered

    def download(self):
        for result in self.get_projects().findall('project'):
            prj = result.get('name')

            if self.cfg.filter and not re.match(self.cfg.filter, prj):
                continue

            archs = result.xpath('repository/arch')
            rpms = []
            for arch in archs:
                ret = self.osc.build.get_binary_list(prj, 'devbuild', arch, 'klp')
                rpm_name = '{}.rpm'.format(arch)
                for rpm in ret.xpath('binary/@filename'):
                    if not rpm.endswith(rpm_name):
                        continue

                    if 'preempt' in rpm:
                        continue

                    # Create a directory for each arch supported
                    dest = Path(self.cfg.bsc_download, str(arch))
                    dest.mkdir(exist_ok=True)

                    rpms.append( (prj, prj, 'devbuild', arch, 'klp', rpm, dest) )

            print('Downloading {} packages'.format(prj))
            self.do_work(self.download_binary_rpms, rpms)

    def status(self):
        prjs = {}
        for prj in self.get_project_names():
            prjs[prj] = {}

            for res in self.osc.build.get(prj).findall('result'):
                code = res.xpath('status/@code')[0]
                prjs[prj][res.get('arch')] = code

        for prj, archs in prjs.items():
            st = []
            for k, v in archs.items():
                st.append('{}: {}'.format(k, v))
            print('{}\t{}'.format(prj, '\t'.join(st)))

    def cleanup(self):
        prjs = self.get_project_names()

        if len(prjs) == 0:
            return

        print('{} projects found.'.format(len(prjs)))

        prjs = self.apply_filter(prjs)

        print('Deleting {} projects...'.format(len(prjs)))

        self.do_work(self.delete_project, prjs)

    def cs_to_project(self, cs):
        return self.prj_prefix + '-' + cs.replace('.', '_')

    # Some attributes are set by default on osctiny:
    # build: enable
    # publish: disable
    def create_prj_meta(self, prj, jcs):
        prj = ET.Element('project', { 'name' : prj})

        debug = ET.SubElement(prj, 'debuginfo')
        ET.SubElement(debug, 'disable')

        ET.SubElement(prj, 'person', { 'userid' : 'mpdesouz', 'role' : 'bugowner'})

        repo = ET.SubElement(prj, 'repository', {'name' : 'devbuild'})
        ET.SubElement(repo, 'path', {'project' : jcs['project'],
                                     'repository' : jcs['repo']
                                     })

        for arch in jcs['archs']:
            ar = ET.SubElement(repo, 'arch')
            ar.text = arch

        return ET.tostring(prj).decode()

    def create_lp_package(self, cs):
        jcs = self.cfg.codestreams[cs]

        prj = self.cs_to_project(cs)

        # If the project exists, drop it first
        self.delete_project(prj, verbose=False)

        meta = self.create_prj_meta(prj, jcs)
        prj_desc = 'Development of livepatches for SLE{}-SP{} Update {}' \
                .format(jcs['sle'], jcs['sp'], jcs['update'])

        try:
            self.osc.projects.set_meta(prj, metafile=meta, title='',
                                       bugowner='mpdesouza',
                                       maintainer='mpdesouza',
                                       description=prj_desc)

            self.osc.packages.set_meta(prj, 'klp', title='', description='Test livepatch')

            print('\t{}: ok'.format(prj))

        except Exception as e:
            print(e, e.response.content)
            raise RuntimeError('')

    def push(self):
        cs_list = self.apply_filter(self.cfg.codestreams.keys())

        if cs_list:
            print('Pushing projects to IBS...')

        # More threads makes OBS to return error 500
        self.do_work(self.create_lp_package, cs_list, 1)
