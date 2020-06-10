#!/usr/bin/python
"""
Library used to provide the appropriate data dir for cloud test.
"""
import os
import glob
import shutil
import stat

from avocado.core import data_dir

_ROOT_PATH = os.path.realpath(os.path.dirname(os.path.dirname(__file__)))
ROOT_DIR = os.path.abspath(_ROOT_PATH)
DATA_DIR = os.path.join(data_dir.get_data_dir(), 'avocado-cloud')


class SubdirList(list):
    """
    List of all non-hidden subdirectories beneath basedir
    """
    def __in_filter__(self, item):
        if self.filterlist:
            for _filter in self.filterlist:
                if item.count(str(_filter)):
                    return True
            return False
        else:
            return False

    def __set_initset__(self):
        for dirpath, dirnames, filenames in os.walk(self.basedir):
            del filenames  # not used
            # Don't modify list while in use
            del_list = []
            for _dirname in dirnames:
                if _dirname.startswith('.') or self.__in_filter__(_dirname):
                    # Don't descend into filtered or hidden directories
                    del_list.append(_dirname)
                else:
                    self.initset.add(os.path.join(dirpath, _dirname))
            # Remove items in del_list from dirnames list
            for _dirname in del_list:
                del dirnames[dirnames.index(_dirname)]

    def __init__(self, basedir, filterlist=None):
        self.basedir = os.path.abspath(str(basedir))
        self.initset = set([self.basedir])  # enforce unique items
        self.filterlist = filterlist
        self.__set_initset__()
        super(SubdirList, self).__init__(self.initset)


class SubdirGlobList(SubdirList):
    """
    List of all files matching glob in all non-hidden basedir subdirectories
    """
    def __initset_to_globset__(self):
        globset = set()
        for dirname in self.initset:  # dirname is absolute
            pathname = os.path.join(dirname, self.globstr)
            for filepath in glob.glob(pathname):
                if not self.__in_filter__(filepath):
                    globset.add(filepath)
        self.initset = globset

    def __set_initset__(self):
        super(SubdirGlobList, self).__set_initset__()
        self.__initset_to_globset__()

    def __init__(self, basedir, globstr, filterlist=None):
        self.globstr = str(globstr)
        super(SubdirGlobList, self).__init__(basedir, filterlist)


def get_root_dir():
    return ROOT_DIR


def get_data_dir():
    return DATA_DIR


def get_tmp_dir(public=True):
    """
    Get the most appropriate tmp dir location.

    :param public: If public for all users' access
    """
    tmp_dir = data_dir.get_tmp_dir()
    if public:
        tmp_dir_st = os.stat(tmp_dir)
        os.chmod(
            tmp_dir, tmp_dir_st.st_mode | stat.S_IXUSR | stat.S_IXGRP
            | stat.S_IXOTH | stat.S_IRGRP | stat.S_IROTH)
    return tmp_dir


def clean_tmp_files():
    tmp_dir = get_tmp_dir()
    if os.path.isdir(tmp_dir):
        hidden_paths = glob.glob(os.path.join(tmp_dir, ".??*"))
        paths = glob.glob(os.path.join(tmp_dir, "*"))
        for path in paths + hidden_paths:
            shutil.rmtree(path, ignore_errors=True)


if __name__ == '__main__':
    print("root dir:         " + ROOT_DIR)
    print("tmp dir:          " + get_tmp_dir())
    print("data dir:         " + DATA_DIR)
