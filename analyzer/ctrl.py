#!/usr/bin/env python2

import os
import sys
import re
import copy
import optparse
import subprocess
import random
import multiprocessing as mp

import utils
import fsop

from functools  import wraps
from os.path    import join
from contextlib import contextmanager


ROOT  = os.path.abspath(os.path.dirname(__file__))
LINUX = os.path.normpath(join(ROOT, "../../linux"))
CLANG = join(ROOT, "../bin/llvm/bin/clang")
FSCK  = join(ROOT, "../llvm/tools/clang/tools/scan-build/fss-build")

try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

@contextmanager
def chdir(pn):
    cwd = os.getcwd()
    os.chdir(pn)
    yield
    os.chdir(cwd)

def get_all_cmds():
    for k, f in globals().items():
        if k.startswith("cmd_"):
            yield (k[4:], f)

def get_cmd(cmd):
    func = "cmd_%s" % cmd
    return globals().get(func, None)

def invoke_cmd(cmd, opts, args):
    func = get_cmd(cmd)
    return func(opts, args)

def fs_args(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if len(args[1]) == 0:
            print("ERROR: should provide fs names")
            exit(1)

        return func(*args, **kwargs)
    return wrapped

# path utils
def mkdirp(out_d):
    if not os.path.exists(out_d):
        os.makedirs(out_d)

def _get_sample_dir(fs):
    return join(ROOT, "out", fs, "sample-log")

def _get_clang_dir(fs):
    return join(ROOT, "out", fs, "clang-log")

def _get_merged_file(fs):
    return join(ROOT, "out", fs, "one.c")

def _get_fss_file(fs):
    import parser

    out_d = _get_clang_dir(fs)
    fss = None
    for pn in parser.Parser(out_d).get_files():
        if pn.endswith("one.c.fss"):
            fss = pn
            break
    return fss

# runner
def _run_merger(fs, linux):
    p = subprocess.Popen([os.path.join(ROOT, "merger.py"),
                          "-l", linux,
                          fs])
    print("[%s] merging %s" % (p.pid, fs))
    return p.wait()

def _run_clang(fs, clang):
    one_d = join(ROOT, "out", fs)
    if not os.path.exists(one_d):
        print("ERROR: %s doesn't exist (need to merge first)" % one_d)
        return None

    out_d = join(ROOT, "out", fs, "clang-log")

    # could you tweak this to run clang pass
    env = copy.copy(os.environ)
    env["CCC_CC"] = clang
    env["CLANG"] = clang

    mkdirp(out_d)

    clang_result = join(out_d, "fss_output")
    clang_stdout = open(join(out_d, "log.stdout"), "w")
    clang_stderr = open(join(out_d, "log.stderr"), "w")

    with chdir(one_d):
        env["PWD"] = os.getcwd()
        p = subprocess.Popen([FSCK,
                              "--use-analyzer=%s" % clang,
                              "--fss-output-dir=%s" % clang_result,
                              "make",
                              "CC=%s" % clang,
                              "-f", "Makefile.build"],
                             stdout=clang_stdout,
                             stderr=clang_stderr,
                             cwd=os.getcwd(),
                             env=env)
        print("[%s] parsing %s" % (p.pid, fs))
        p.wait()

    del clang_stdout
    del clang_stderr

def simple_mp_fs(fn, args):
    if len(args) == 0:
        args = fsop.get_all_fs()

    pool = mp.Pool(mp.cpu_count())
    for fs in args:
        pool.apply_async(fn, args=(fs,))
    pool.close()
    pool.join()

# cmds
@fs_args
def cmd_merge(opts, args):
    """merge fs specified (e.g., 'merge ext3 ext4')"""

    import merger
    for fs in args:
        merger.merge_fs(opts, fs)

def cmd_merge_all(opts, _):
    """merge all fs (e.g., 'merge_all')"""

    pool = mp.Pool(mp.cpu_count())
    for fs in fsop.get_fs("M"):
        pool.apply_async(_run_merger, args = (fs, opts.linux))
    pool.close()
    pool.join()

    return 0

@fs_args
def cmd_clang(opts, args):
    """run clang pass (e.g., 'clang ext3 ext4)"""

    pool = mp.Pool(mp.cpu_count())
    for fs in args:
        pool.apply_async(_run_clang, args=(fs, opts.clang))
    pool.close()
    pool.join()

def cmd_clang_vfs(opts, args):
    """run clang pass (e.g., 'clang ext3 ext4)"""

    pool = mp.Pool(mp.cpu_count())
    for fs in args:
        vfs_fs = "vfs_" + fs
        pool.apply_async(_run_clang, args=(vfs_fs, opts.clang))
    pool.close()
    pool.join()

def cmd_clang_all(opts, _):
    """run clang pass on all fs (e.g., 'clang_all)"""

    pool = mp.Pool(mp.cpu_count())
    for fs in fsop.get_fs("C"):
        pool.apply_async(_run_clang, args=(fs, opts.clang))
    pool.close()
    pool.join()

    return 0

def cmd_clang_vfs_all(opts, _):
    """run clang pass on all fs (e.g., 'clang_all)"""

    pool = mp.Pool(mp.cpu_count())
    for fs in fsop.get_fs("C"):
        vfs_fs = "vfs_" + fs
        pool.apply_async(_run_clang, args=(vfs_fs, opts.clang))
    pool.close()
    pool.join()

    return 0

def cmd_grep_decl(opts, args):
    """grep common fields (e.g., 'grep_decl ext4')"""

    if len(args) == 0:
        args = fsop.get_all_fs()

    for fs in args:
        fsop.dump_known_ops(os.path.join(opts.linux, "fs", fs))

def cmd_merge_vfs(opts, args):
    """merge the vfs code with existing fs"""

    import merger
    for fs in args:
        merger.merge_vfs_fs(opts, fs)

def cmd_merge_vfs_all(opts, _):
    """merge all fs (e.g. 'merge_all')"""

    print "will implement it soon"
    pass

def cmd_pickle_all(opts, args):
    """parsing and pickling clang analysis results (e.g. pickle_all ./out)"""

    import pickler
    log_d = args[0] if args != [] else os.path.join(ROOT, "out")
    pickler.parse_and_pickle(log_d)
    return 0

def cmd_sample_fss(opts, args):
    """sample paths per return"""

    for fs in args:
        _get_sample_fss(fs)

def _get_sample_fss(fs):
    one = _get_merged_file(fs)
    if not os.path.exists(one):
        print("ERROR: %s doesn't exist (need to merge first)" % one)
        return None

    fss = _get_fss_file(fs)
    if not fss:
        print("ERROR: can't find .fss please run clang first")
        return None

    def _dump_to(fss, out):
        maps = set()
        with open(fss) as fd:
            state_skip = False
            for l in fd:
                if l.startswith("@LOCATION"):
                    if l in maps:
                        state_skip = True
                    else:
                        maps.add(l)
                        state_skip = False
                if not state_skip:
                    out.write(l)

    out_d = join(ROOT, "out", fs, "sample-log")
    mkdirp(out_d)

    with open(join(out_d, "%s.fss" % fs), "w") as fd:
        _dump_to(fss, fd)

def _analyze_lock(fs):
    import lock

    fss_d = join(ROOT, "out", fs, "clang-log")
    out_d = join(ROOT, "results", fs)

    mkdirp(out_d)

    assert all(os.path.exists(d) for d in [fss_d, out_d])

    lock.analyze_fs(fs, out_d, fss_d)

def cmd_analyze_lock(opts, args):
    """analyze lock usage (e.g., analyze_lock [fs])"""

    simple_mp_fs(_analyze_lock, args)

def _analyze_lock_range(fs):
    import lock_range

    fss_d = join(ROOT, "out", fs, "clang-log")
    out_d = join(ROOT, "results", fs)

    mkdirp(out_d)

    assert all(os.path.exists(d) for d in [fss_d, out_d])

    lock_range.analyze_fs(fs, out_d, fss_d)

def cmd_analyze_lock_range(opts, args):
    """analyze lock range (e.g., analyze_lock_range [fs])"""

    simple_mp_fs(_analyze_lock_range, args)

def _analyze_lock_promo(fs):
    pass

def cmd_analyze_lock_promo(opts, args):
    """analyze lock usage (e.g., analyze_lock_promo [fs])"""

    simple_mp_fs(_analyze_lock_promo, args)

def cmd_status(opts, args):
    """check status of merge/clang"""

    def _get_size(pn):
        if pn is None or not os.path.exists(pn):
            return 0
        return os.stat(pn).st_size

    for fs in fsop.get_all_fs():
        one = _get_merged_file(fs)
        fss = _get_fss_file(fs)

        print "%-10s %10s B %10s B" % (fs, _get_size(one), _get_size(fss))


if __name__ == '__main__':
    utils.install_pdb()

    parser = optparse.OptionParser()
    parser.add_option("--linux", help="Linux kernel", default=LINUX)
    parser.add_option("--clang", help="Clang path", default=CLANG)
    parser.add_option("--outdir", help="Clang output dir", default="/tmp")
    (opts, args) = parser.parse_args()

    def __print_usage(note):
        print(note)
        for (cmd, func) in get_all_cmds():
            print("> %-20s: %s" % (cmd, func.__doc__))
        exit(0)

    if len(args) == 0:
        __print_usage("Need to specify a command")

    cmd = args[0]
    if get_cmd(cmd) is None:
        __print_usage("Can't find the command, '%s'" % cmd)

    exit(invoke_cmd(cmd, opts, args[1:]))
