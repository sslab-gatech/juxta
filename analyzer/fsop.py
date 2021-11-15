#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import re
import pprint

import utils
import dbg

ROOT = os.path.dirname(__file__)

# XXX. hide
def load_conf(pn):
    conf = []
    for l in open(pn):
        m = re.match("\[([\\w ]*)\] (\\w+).*", l)
        if m:
            tok = m.groups()
            conf.append((tok[0].strip(), tok[1]))
    return conf

global CONF
CONF = load_conf(os.path.join(ROOT, "NOTE.fs"))

def get_fs(kind):
    global CONF
    rtn = []
    for (tag, fs) in CONF:
        if all(t in tag for t in kind):
            rtn.append(fs)
    return rtn

def get_all_fs():
    return get_fs("")

def dump_known_ops(fs_d):
    STRUCTS = [
        "export_operations",            # 9
        "address_space_operations",     #19
        "file_lock_operations",         # 2
        "lock_manager_operations",      # 9
        "block_device_operations",      # X
        "file_operations",              #30
        "inode_operations",             #27
        "super_operations",             #25
        "dentry_operations",            #11
        "file_system_type",             # 2
        "vm_operations_struct",         #10
        "seq_operations",               # 4
        "quotactl_ops",                 #12
        "sysfs_ops",                    # 2
        "dquot_operations",             # 8
        "xattr_handler"]                # 3  -> 173

    def __grep_struct(fd):
        for l in fd:
            l = l.strip()
            # drop CONF
            if any(l.startswith(c) for c in ["#", "/", '*']):
                continue
            print "  %s" % l
            if l.endswith("};"):
                break

    def __normalize(name):
        pos = name.find("struct")
        return name[pos+7:].strip()

    def __grep(fd):
        for line in fd:
            line = line.strip()
            if not line.endswith("{"):
                continue

            if any("struct " + s in line for s in STRUCTS):
                print __normalize(line)
                __grep_struct(fd)

    for root, dirs, files in os.walk(fs_d):
        for name in files:
            pn = os.path.join(root, name)
            with open(pn) as fd:
                __grep(fd)

def normalize_fops(pn):
    RULES = {
        "inode_operations (\w+)_file_inode_operations"           : "%s/inode/file",
        "vm_operations_struct (\w+)_file_vm_ops"                 : "%s/vm/file",
        "vm_operations_struct (\w+)_mmap_file_vm_ops"            : "%s/vm/mmap",
        "inode_operations (\w+)_symlink_inode_operations"        : "%s/inode/symlink",
        "inode_operations (\w+)_dir_inode_operations"            : "%s/inode/dir",
        "inode_operations (\w+)_special_inode_operations"        : "%s/inode/special",
        "inode_operations (\w+)_(\w+)_iops"                      : "%s/inode/%s",
        "file_operations (\w+)_(\w+)_operations"                 : "%s/file/%s",
        "file_operations (\w+)_(\w+)_fops"                       : "%s/file/%s",
        "file_operations (\w+)_cached_file_operations"           : "%s/file/cached",
        "file_operations (\w+)_fops"                             : "%s/file/file",
        "xattr_handler (\w+)_xattr_acl_access_handler"           : "%s/xattr/access",
        "xattr_handler (\w+)_xattr_acl_default_handler"          : "%s/xattr/default",
        "xattr_handler (\w+)_xattr_(\w+)_handler"                : "%s/xattr/%s",
        "address_space_operations (\w+)_symlink_addr_operations" : "%s/addr/symlink",
        "address_space_operations (\w+)_addr_operations"         : "%s/addr/addr",
        "address_space_operations (\w+)_aops"                    : "%s/addr/addr",
        "dentry_operations (\w+)_cached_dentry_operations"       : "%s/dentry/cached",
        "dentry_operations (\w+)_dentry_operations"              : "%s/dentry/dentry",
        "dentry_operations (\w+)_ops"                            : "%s/dentry/dentry",
        "super_operations (\w+)_super_ops"                       : "%s/super/super",
        "super_operations (\w+)_sops"                            : "%s/super/super",
        "super_operations (\w+)_super_operations"                : "%s/super/super",
        "super_operations (\w+)_ops"                             : "%s/super/super",
        "file_system_type (\w+)_fs_type"                         : "%s/fs/fs",
        "file_system_type (\w+)_type"                            : "%s/fs/fs",
        "export_operations (\w+)_export_operations"              : "%s/export/export",
        "export_operations (\w+)_export_ops"                     : "%s/export/export",
        "file_operations (\w+)_ctl_fops"                         : "%s/file/ctl",
        "vm_operations_struct (\w+)_vmops"                       : "%s/vm/vm",
        "vm_operations_struct (\w+)_vm_ops"                      : "%s/vm/vm",
        "sysfs_ops (\w+)_(\w+)_ops"                              : "%s/sysfs/%s",
        "seq_operations (\w+)_seq_ops"                           : "%s/seq/seq",
    }
    for line in (open(pn)):
        line = line.strip().replace(" = {", " {")
        if not line.endswith("{"):
            if "=" in line:
                (lhs, rhs) = line.split("=", 1)
                lhs = lhs.strip()
                rhs = rhs.strip()
                print"  %-20s= %s" % (lhs, rhs)
                continue
            print "%s" % line
            continue

        name = line.rstrip("{ = ")
        rewritten = False
        for (r, out) in RULES.iteritems():
            m = re.match(r, name)
            if m:
                print("%s {" % out % m.groups())
                rewritten = True
                break
        if not rewritten:
            print line

def _load_fops(pn):

    def _load_struct(fd):
        pair = {}
        for l in fd:
            l = l.strip()
            if "};" in l or l.startswith("&") or l == "":
                break
            dbg.trace("%s", l)
            (lhs, rhs) = l.split("=")
            lhs = lhs.lstrip(".").strip()
            rhs = rhs.rstrip(" ,").strip()
            pair[lhs] = rhs
        return pair

    conf = []
    fd = open(pn)
    for l in fd:
        l = l.strip()
        if l == "" or l.startswith("#"):
            continue
        if l.endswith("{"):
            val = _load_struct(fd)
            key = l.rstrip(" {").split("/")
            dbg.trace("%s", key)
            if len(key) == 0:
                continue
            conf.append((key, val))
    return conf

# XXX. remove after cleaning fops-3/4
dbg.quiet(["trace"])
global FOPS
FOPS = _load_fops("NOTE.fops-4.0")

def get_ops(*specifiers):
    def _match(key, specifiers):
        # XXX. not completely trimmed yet
        if len(key) == 1:
            return False

        for (k, s) in zip(key, specifiers):
            if type(s) == list:
                if not k in s:
                    return False
                continue
            if not (s == "*" or k == s):
                return False
        return True

    rtn = []
    global FOPS
    for (key, val) in FOPS:
        if _match(key, specifiers):
            rtn.append((key, val))
    return rtn

def get_all_fs_entry_funcs():
    return get_fs_entry_funcs("*", "*")

def get_fs_entry_funcs(*specifiers):
    funcs = set()
    for k, xs in get_ops(*specifiers):
        funcs.update(xs.values())
    return list(funcs)

def get_matched_ops(*specifiers):
    matchDict = {}
    for k, xs in get_ops(*specifiers):
        for op, fn in xs.iteritems():
            key = "%s-%s-%s" % (op, k[1], k[2])
            match_funcs = matchDict.get(key, [])
            match_funcs.append(fn)
            matchDict[key] = match_funcs
    match_list = matchDict.values()
    return match_list

if __name__ == '__main__':
    pprint.pprint(get_matched_ops("*", "inode"))
    # utils.install_pdb()
    # normalize_fops("NOTE.fops-4.0")
    pprint.pprint(get_all_fs_entry_funcs())

    # query ext4/inode/*
    # pprint.pprint(get_ops("ext4", "inode"))
    # query */inode/file
    # pprint.pprint(get_ops("*", "inode", "file"))
    # query "ext4" or "btrfs"
    # pprint.pprint(get_ops(["ext4", "btrfs"], "inode"))
