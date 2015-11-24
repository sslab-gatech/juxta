#!/usr/bin/env python2

import os
import sys
import re
import shutil
import pprint
import glob
import optparse

from collections import Counter
from collections import defaultdict

import pymake.parser

from pygments            import highlight
from pygments.formatters import HtmlFormatter
from pygments.formatter  import Formatter
from pygments.lexers     import CLexer
from pygments.token      import *

ROOT  = os.path.abspath(os.path.dirname(__file__))
LINUX = os.path.normpath(os.path.join(ROOT, "../../linux"))

# manual opt out
#  (see, logfs defines hash_32() which was included by other c files)
global FS_FORCE_REWRITE
FS_FORCE_REWRITE = {
    "logfs": ["hash_32"],
    "minix": ["DIRECT", "DEPTH", "block_t", "Indirect", "pointers_lock", "block_to_cpu"],
    "ncpfs": ["ncp_symlink", "ncp_symlink_readpage"],
    "jffs2": ["deflate_mutex"],
    "nfsd" : ["NFSDDBG_FACILITY", "nfs3_ftypes"],
}

def _load_btrfs(pn):
    # XXX. move build_backref_tree relocation.c at the end
    if os.path.basename(pn) == "relocation.c":
        code = open(pn).readlines()

        backref_dec = None
        backref_beg = None
        backref_end = None

        DECL = "struct backref_node *build_backref_tree"
        for (i, l) in enumerate(code):
            if l.startswith(DECL):
                backref_dec = i
                continue
            if backref_dec and l.startswith("{"):
                backref_beg = i
                continue
            if backref_dec and l.startswith("}"):
                backref_end = i
                break
        assert(all([backref_dec, backref_beg, backref_end]))

        # basically, move it to the end
        return "".join(code[:backref_beg] + [";"] \
                + code[backref_end+1:] + ["\n"] \
                + code[backref_dec-1:backref_end+1])

    _load_file(pn)

global FS_CODE_LOADER
FS_CODE_LOADER = {
    "btrfs": _load_btrfs,
}

def load_fs_file(fs, pn):
    global FS_CODE_LOADER

    loader = FS_CODE_LOADER.get(fs, load_file)
    return loader(pn)


class TokenRewritter(Formatter):
    def __init__(self, pn, plan):
        self.pn = pn
        self.plan = plan
        self.syms = plan[pn]
        self.stat = Counter()
        self.lookup = []

    def is_dot_tok(self, token, value):
        return token is Token.Punctuation and value == "."

    def format(self, tokensource, outfile):
        lookup = []
        for ttype, value in tokensource:
            # tokens used in macro
            if ttype is Token.Comment.Preproc:
                for (k, v) in self.syms.iteritems():
                    if k in value:
                        print("> rewrite (mcro) %s -> %s" % (k, v))
                        value = value.replace(k, v)
                        self.stat[value] += 1
            # check regular function call
            if ttype is Token.Name \
                    and not self.is_dot_tok(*lookup[-1]):
                #
                # NOTE (ignore, wrong pygment parser)
                #   struct.func_ptr => [Token.Punctuation][Toen.Name]
                #
                new_sym = self.syms.get(value, None)
                if new_sym:
                    self.stat[value] += 1
                    print("> rewrite (call) %s -> %s" % (value, new_sym))
                    value = new_sym

            # check func decls
            if ttype is Token.Name.Function or ttype is Token.Keyword.Type:
                new_sym = self.syms.get(value, None)
                if new_sym:
                    print("> rewrite (decl) %s -> %s" % (value, new_sym))
                    value = new_sym

            lookup.append((ttype, value))

            outfile.write(value)
            lookup.append((ttype, value))


class StaticDecl(Formatter):
    def __init__(self):
        self.table = set()
        # NOTE. nothing yet
        self.blacklist = set(["nfsd3_voidargs"])

    def is_dot_tok(self, token, value):
        return token is Token.Punctuation and value == "."

    def format(self, tokensource, outfile):
        lookup = []
        for ttype, value in tokensource:
            # strong blacklisting
            if value in self.blacklist:
                continue
            if ttype is Token.Name.Function:
                # e.g., DEFINE_SPINLOCK() or DEFINE_RWLOCK()
                if value.startswith("DEFINE_") \
                   or value.startswith("LIST_HEAD") \
                   or value.startswith("LLIST_HEAD") \
                   or value.startswith("DECLARE_DELAYED_WORK"):
                    continue

                # NOTE. arbitrary tokens can be inserted before static
                # shows up, but usually 5.
                is_static = False
                for i in range(8):
                    if lookup[-i][0] is Token.Keyword \
                       and lookup[-i][1] == "static":
                        self.table.add(value)
                        break
            if ttype is Token.Punctuation and value == "{":
                struct_name = None
                struct_keyword = None
                for i in range(5):
                    (typ, val) = lookup[-i]
                    if typ is Token.Keyword and val == "struct":
                        struct_keyword = True
                        break
                    if typ is Token.Name and struct_keyword is None:
                        struct_name = val

                if struct_keyword and struct_name:
                    self.table.add(struct_name)

            lookup.append((ttype, value))


# utils
def dump_to_file(pn, contents):
    with open(pn, "w") as fd:
        fd.write(contents)

def dump_symbols_to_file(dst_d, name, syms):
    with open(os.path.join(dst_d, name), "w") as fd:
        for pn in syms:
            pprint.pprint("> %s" % pn, fd)
            pprint.pprint(syms[pn], fd)

def load_file(*pn):
    with open(os.path.join(*pn)) as fd:
        return fd.read()

def do_copy(src, dst):
    dst_d = os.path.dirname(dst)
    if not os.path.exists(dst_d):
        os.makedirs(dst_d)
    shutil.copyfile(src, dst)

# parse and prepare conflicted symbols
def prepare_rewritting(target, codes):
    global FS_FORCE_REWRITE

    def _to_canonical(pn, sym):
        base = os.path.basename(pn)
        return sym + "_" + base.replace(".", "_").replace("-", "_")

    # get static symbols
    static_symbols = {}
    for (pn, code) in codes:
        formatter= StaticDecl()
        highlight(code, CLexer(), formatter)

        print("> %-50s: %d" % (pn, len(formatter.table)))
        static_symbols[pn] = formatter.table

    # check collisions
    rewriting_plan = defaultdict(dict)
    for (pivot_pn, pivot_tbl) in static_symbols.iteritems():
        # rewrite if collapsed
        for sym in pivot_tbl:
            for (target_pn, target_tbl) in static_symbols.iteritems():
                if pivot_pn == target_pn:
                    continue
                if sym in target_tbl:
                    print("> %s collaposed with %s & %s" % (sym, pivot_pn, target_pn))
                    rewriting_plan[pivot_pn][sym] = _to_canonical(pivot_pn, sym)

        # update pivot_tbl to minize rewriting
        for (sym, new_sym) in rewriting_plan[pivot_pn].iteritems():
            pivot_tbl.remove(sym)
            pivot_tbl.add(new_sym)

    # manual rewriting (e.g., collision in headers)
    for sym in FS_FORCE_REWRITE.get(target, []):
        print("> manually include %s" % sym)
        for (pivot_pn, pivot_tbl) in static_symbols.iteritems():
            rewriting_plan[pivot_pn][sym] = _to_canonical(pivot_pn, sym)

    return (static_symbols, rewriting_plan)

# copy/generate necessary files for building a kernel module
def prepare_dir(fs, linux, src_d, dst_d, cflags):
    if not os.path.exists(dst_d):
        os.makedirs(dst_d)

    # copy non '.c' file
    for root, dirs, files in os.walk(src_d):
        for name in files:
            src = os.path.join(root, name)
            dst = os.path.join(dst_d, src[len(src_d)+1:])

            if not any(src.endswith(ext) for ext in [".c", ".o", ".cmd", ".d"]):
                print("> copy %-50s -> %s" % (os.path.relpath(src), dst))
                do_copy(src, dst)

    # makefiles
    with open(os.path.join(dst_d, "Makefile.build"), "w") as fd:
        fd.write("""\
KBUILD := %s
all:
	make -C $(KBUILD) M=$(PWD) modules
clean:
	make -C $(KBUILD) M=$(PWD) clean
        """ % os.path.abspath(linux))

    with open(os.path.join(dst_d, "Makefile"), "w") as fd:
        fd.write("""\
%s
obj-m += %s.o
%s-y := one.o
""" % ("\n".join(cflags), fs, fs))

# vfs specific
def prepare_vfs_dir(fs, linux, src_d, dst_d, cflags):
    if not os.path.exists(dst_d):
        os.makedirs(dst_d)

    # copy non '.c' file
    files = [ f for f in os.listdir(src_d) if \
            os.path.isfile(os.path.join(src_d, f)) ]
    for name in files:
        src = os.path.join(src_d, name)
        dst = os.path.join(dst_d, src[len(src_d)+1:])

        if not any(src.endswith(ext) for ext in [".c", ".o", ".cmd", \
                ".d", "Makfile", ".binfmt"]):
            print("> copy %-50s -> %s" % (os.path.relpath(src), dst))
            do_copy(src, dst)

# utils for handling makefile
def load_kconfig(pn):
    conf = {}
    for l in open(pn):
        l = l.strip()
        if l == "" or l.startswith("#"):
            continue
        assert("=" in l)
        (lhs, rhs) = l.split("=")
        conf[lhs.strip()] = rhs.strip()
    assert(len(conf) > 0)
    return conf

def iter_make_rules(pn):
    for stmt in pymake.parser.parsestring(load_file(pn), pn):
        tgt = stmt.vnameexp.to_source()
        dep = stmt.value
        yield (tgt, dep)

def iter_make_stmts(pn):
    for stmt in pymake.parser.parsestring(load_file(pn), pn):
        yield stmt.to_source()

def parse_makefile(kconf, src_d):
    mk = os.path.join(src_d, "Makefile")

    target = []
    files = []

    for (tgt, dep) in iter_make_rules(mk):
        if tgt.startswith("obj-"):
            # NOTE. pick first obj (only ocfs2 matters)
            dep = dep.split()[0]
            target.append(dep.replace(".o", ""))

    # NOTE. see, fat/Makefile
    #   multiple obj targets are used
    if len(target) > 1:
        print("! NOTE. more than one obj targets")

    target = target[0]
    for (tgt, dep) in iter_make_rules(mk):
        if tgt.startswith(target + "-"):
            if "$" in tgt:
                m = re.match(".*-\$\(([^\)]+)\)", tgt)
                if m.groups()[0] not in kconf:
                    continue
            for s in dep.split():
                if s.endswith(".o"):
                    s = s.replace(".o", ".c")
                    if not s in files:
                        files.append(s)
                else:
                    print("! NOTE. require expansion on rule, but ignored")

    # e.g., hppfs.c
    if os.path.exists(os.path.join(src_d, target + ".c")):
        files.append(target + ".c")

    cflags = []
    for stmt in iter_make_stmts(mk):
        if stmt.startswith("ccflags-y"):
            cflags.append(stmt)

    return (target, files, cflags)

def parse_vfs_makefile(kconf, src_d):
    mk = os.path.join(src_d, "Makefile")

    files = []
    rfiles = ["proc_namespace.o", "signalfd.o", "timerfd.o", "eventfd.o", "binfmt_aout.o", \
            "binfmt_em86.o", "binfmt_em86.o", "binfmt_misc.o", "binfmt_script.o", \
            "binfmt_elf.o", "compat_binfmt_elf.o", "binfmt_elf_fdpic.o", "binfmt_flat.o" \
            "coredump.o", "pipe.o", "fcntl.o"]

    for (tgt, dep) in iter_make_rules(mk):
        if tgt.startswith("obj" + "-"):
            if "$" in tgt:
                m = re.match(".*-\$\(([^\)]+)\)", tgt)
                if m.groups()[0] not in kconf:
                    continue
            for s in dep.split():
                if s.endswith(".o"):
                    if s in rfiles:
                        continue
                    files.append(s.replace(".o", ".c"))
                else:
                    print("! NOTE. require expansion on rule, but ignored")
    cflags = []
    for stmt in iter_make_stmts(mk):
        if stmt.startswith("ccflags-y"):
            cflags.append(stmt)

    return (files, cflags)


# adjust c code to point to a right one
def adjust_file_path(src_d, files):
    fullpath = []
    for f in files:
        pn = os.path.join(src_d, f)
        if not os.path.exists(pn):
            optimitic = glob.glob(os.path.join(src_d, "*", f))
            if len(optimitic) == 1:
                print("! WARNING: not found %s, but use %s" % (pn, optimitic[0]))
                pn = optimitic[0]
            else:
                print("! not found %s" % pn)
                exit(1)
        fullpath.append(os.path.relpath(pn))

    return fullpath

# preprocess headers
def preprocess_headers(fs, src_d, code, headers):
    prev_inc = False
    for l in code.splitlines():
        m = re.match('#[ \t]*include[ \t]*[<"]([^>"]+)[">]', l)
        if m:
            inc = m.groups()[0]

            # NOTE. include ".c" (by minix)
            if inc.endswith('.c'):
                print "> inlining %s" % inc

                # inlining .c code
                yield "/* inlined: " + inc + "*"*40 + "/"
                inlined_code = load_fs_file(fs, os.path.join(src_d, inc))
                for l in preprocess_headers(fs, src_d, inlined_code, headers):
                    yield l
                yield "/" + "*"*60 + "/"

                continue

            if inc in headers:
                l = "// %s" % l
            else:
                headers.add(inc)
                prev_inc = True
        elif prev_inc:
            yield "#include \"../../inc/__fss.h\""
            if os.path.exists(os.path.join(ROOT, "inc", "__%s.h" % fs)):
                yield "#include \"../../inc/__%s.h\"" % fs
            prev_inc = False
        yield l

# opt out headers & expand
def preprocess(fs, src_d, files):
    headers = set()
    codes = []
    for f in files:
        with open(f) as fd:
            code = []
            for l in preprocess_headers(fs, src_d, fd.read(), headers):
                code.append(l)
            code = "\n".join(code)
            codes.append((f, code))

    return codes

# rewrite codes and flush them to out
def rewrite(fs, codes, out):
    with open(out, "w") as fd:
        (static_symbols, rewriting_plan) = prepare_rewritting(fs, codes)
        for (pn, code) in codes:
            # reschedule static symbols
            rewritten = highlight(code, CLexer(), TokenRewritter(pn, rewriting_plan))
            for l in rewritten.splitlines():
                fd.write(l.encode("utf8"))
                fd.write("\n")

            fd.write("/" + "*" * 60 + "/\n")
            fd.write("/* %s */\n" % pn)
            fd.write("/" + "*" * 60 + "/\n")

    return (static_symbols, rewriting_plan)

def replace_all_in_file(out, sfrom, sto):
    lines = []
    with open(out) as fd:
        for l in fd:
            lines.append(l.replace(sfrom, sto))
    with open(out, "w") as fd:
        fd.write("".join(lines))

# per-fs ad-hoc rewriting come here
def post_adjust_per_fs(fs, dst_d, out):
    if fs == "ocfs2":
        namei = os.path.join(dst_d, "namei.h")
        code = load_file(namei)
        # XXX. it's a bug
        code = code.replace("struct dentry *ocfs2_get_parent",
                            "// struct dentry *ocfs2_get_parent")
        dump_to_file(namei, code)
    elif fs == "ubifs":
        rules = [("old_inode->i_sb->s_op->write_inode", "ubifs_write_inode"),
                 ("inode->i_sb->s_op->write_inode", "ubifs_write_inode")]

        for (l, r) in rules:
            replace_all_in_file(out, l, r)
    elif fs == "nfsd":
        replace_all_in_file(out, "struct nfsd3_voidargs { int dummy; };",
                            "// struct nfsd3_voidargs { int dummy; };")

# process a fs
def merge_fs(opts, fs):
    src_d = os.path.join(opts.linux, "fs", fs)
    dst_d = "out/%s" % fs
    kconf = load_kconfig(os.path.join(opts.linux, ".config"))

    (target, files, cflags) = parse_makefile(kconf, src_d)

    print("> fs   : %s" % target)
    print("> files: %s" % files)

    if fs != target:
        print("! WARNING: you might not want: %s vs %s?" % (fs, target))

    # adjust path
    files = adjust_file_path(src_d, files)

    # copy non-c files
    prepare_dir(fs, opts.linux, src_d, dst_d, cflags)

    # preprocess: opt out headers & expand
    codes = preprocess(fs, src_d, files)

    # rewrite
    out = os.path.join(dst_d, "one.c")
    (out_symbols, out_rewriting) = rewrite(fs, codes, out)

    # kept them for debugging
    dump_symbols_to_file(dst_d, "rewriting.info", out_rewriting)
    dump_symbols_to_file(dst_d, "symbols.info", out_symbols)

    # final touch
    post_adjust_per_fs(fs, dst_d, out)

# process a fs along with vfs
def merge_vfs_fs(opts, fs):
    src_d = os.path.join(opts.linux, "fs")
    src_fs_d = os.path.join(opts.linux, "fs", fs)
    dst_d = "out/vfs_%s" % fs
    kconf = load_kconfig(os.path.join(opts.linux, ".config"))

    (vfs_files, vfs_cflags) = parse_vfs_makefile(kconf, src_d)

    print("> vfs-files: %s" % vfs_files)

    (target, files, cflags) = parse_makefile(kconf, src_fs_d)

    print("> fs   : %s" % target)
    print("> files: %s" % files)

    # adjust path first for fs and then for vfs
    vfs_files = adjust_file_path(src_d, vfs_files)
    files     = adjust_file_path(src_fs_d, files)

    # copy non-c files -> fs and vfs
    prepare_vfs_dir(fs, opts.linux, src_d, dst_d, vfs_cflags)
    prepare_dir(fs, opts.linux, src_fs_d, dst_d, cflags)

    #preprocessing!
    codes = preprocess(fs, src_fs_d, files)
    vfs_codes = preprocess(fs, src_d, vfs_files)

    out = os.path.join(dst_d, "one.c")
    codes += vfs_codes
    (out_symbols, out_rewriting) = rewrite(fs, codes, out)

    # kept them for debugging
    dump_symbols_to_file(dst_d, "rewriting.info", out_rewriting)
    dump_symbols_to_file(dst_d, "symbols.info", out_symbols)

    # final touch
    post_adjust_per_fs(fs, dst_d, out)



if __name__ == "__main__":
    parser = optparse.OptionParser("%s {-l %s} [fs]" % (LINUX, sys.argv[0]))
    parser.add_option("--linux", "-l", help="Linux kernel", default=LINUX)
    parser.add_option("--test", "-t", help="Build after merged", 
                      action="store_true", default=False)
    (opts, args) = parser.parse_args()

    if len(args) == 0:
        parser.error("need to provie a fs name")
        exit(1)

    for fs in args:
        merge_fs(opts, fs)
        if opts.test:
            os.system("cd out/%s; make -f Makefile.build" % fs)
    
