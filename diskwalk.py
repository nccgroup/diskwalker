from __future__ import print_function

## This will probably be release under the AGPL later on

import atexit
import pickle
import os
import sys
import tempfile
import gzip
import errno
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import chain
from functools import partial
from pwd import getpwnam
from mmap import mmap as _mmap, PROT_READ
try:
    from itertools import ifilter as filter
except ImportError:
    pass


if sys.version_info.major > 2:
    access = partial(os.access, follow_symlinks=False)
    mmap = _mmap
else:
    def access(fname, mode=None):
        return os.access(fname, mode)

    from contextlib import closing
    mmap = lambda *args, **kwargs: closing(_mmap(*args, **kwargs))

readable_p = partial(access, mode=os.R_OK)
writable_p = partial(access, mode=os.W_OK)
executable_p = partial(access, mode=os.EX_OK)

def owned_by_user(user_id, f):
    return os.lstat(f).st_uid == user_id

def owned_by_group(group_id, f):
    return os.lstat(f).st_gid == group_id

nobody_uid = getpwnam('nobody').pw_uid
nobody_gid = getpwnam('nobody').pw_gid

owned_by_nobody_p = partial(owned_by_user, nobody_uid)
owned_by_nobody_group_p = partial(owned_by_group, nobody_gid)
owned_by_me_p = partial(owned_by_user, os.getuid())
owned_by_my_group_p = partial(owned_by_group, os.getgid())

def time_since(action, delta, f):
    statattr = {'modification': 'st_mtime', 'creation': 'st_ctime', 'access': 'st_atime'}[action]
    timestamp = getattr(os.lstat(f), statattr)
    return datetime.now() < datetime.fromtimestamp(timestamp) + delta

accessed_since_60minutes_filep = partial(time_since, 'access', timedelta(minutes=60))
modified_since_60minutes_filep = partial(time_since, 'modification', timedelta(minutes=60))
created_since_60minutes_filep = partial(time_since, 'creation', timedelta(minutes=60))

interesting_extensions = ['.' + e for e in 'cfg rtf config txt c pl gz bz2 7z log tar tgz sql properties xml'.split()]

def interesting_filep(fname):
    ext = os.path.splitext(fname)[1].lower()
    return ext in interesting_extensions

def interesting2_filep(fname):
    name = os.path.basename(fname).lower()
    return name in 'shadow password passwd authorized_keys rhosts htaccess htdigest'.split() or \
        any(name.startswith(x) for x in ['identity', 'id_dsa', 'id_rsa']) or \
        os.path.basename(os.path.dirname(fname)) == '.ssh' or '.subversion/auth/svn.simple' in fname or \
        '_hist' in name and name.startswith('.')

def contain_password_filep(fname):
    # to be improved
    if readable_p(fname) and os.lstat(fname).st_size and not os.path.islink(fname):
        with open(fname, 'rb') as fd, mmap(fd.fileno(), 0, prot=PROT_READ) as mm:
            return any(mm.find(keyword) != -1 for keyword in [b'assword'])

def ignore_missing(f):
    def predicate_wrapper(fname):
        try:
            return f(fname)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            return False
    return predicate_wrapper

def get_predicates(suffix):
    l = len(suffix)
    return {name[:-l]: ignore_missing(fun) for name, fun in
            globals().items() if name[-l:] == suffix}


def save_dump(d):
    preferred_dirs = [os.path.abspath('.'), tempfile.gettempdir()]
    tempdir = next(filter(writable_p, chain(preferred_dirs, d['writable_dirs'])))
    outfile = os.path.join(tempdir, 'dump.gz')

    with gzip.open(outfile, 'wb') as out:
        pickle.dump(d, out)

    atexit.register(print, 'the dictionary has been saved in', outfile)


def extract():
    predicates = get_predicates('_p')
    file_predicates = get_predicates('_filep')
    file_predicates.update(predicates)
    d = defaultdict(set)

    for current, dirs, files in os.walk('/'):
        if current == '/':
            del dirs[dirs.index('sys')]
            del dirs[dirs.index('dev')]
            del dirs[dirs.index('proc')]
        localpath = partial(os.path.join, current)

        for pred_name, predicate in file_predicates.items():
            d[pred_name + '_files'].update(filter(predicate, map(localpath, files)))
        for pred_name, predicate in predicates.items():
            d[pred_name + '_dirs'].update(filter(predicate, map(localpath, dirs)))

    save_dump(d)
    return d

def load_dump(fname):
    with gzip.open(fname, 'rb') as f:
        return pickle.load(f)

if __name__ == '__main__':
    args = sys.argv[1:]
    if args:
        d = load_dump(*args)
    else:
        d = extract()

    # if you load the script with -i, you'll now have access to the `d` dictionary here

