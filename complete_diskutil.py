#!/usr/bin/env python
# encoding: utf-8
"""
This script is called by a bash completion function to help complete 
the options for the diskutil os x command

Created by Preston Holmes on 2010-03-11.
preston@ptone.com
Copyright (c) 2010

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import sys
import os
from subprocess import Popen, call, STDOUT, PIPE
import plistlib
import re

cache = '/tmp/completiondiskcache'
DEBUG = False
USE_CACHE = False


def iter_all_filesystem_personalities():
    fsinfo = plistlib.readPlistFromString(sh("diskutil listFilesystems -plist"))
    for fs in fsinfo:
        pers = fs.get("Personality")
        if pers:
            yield pers

def iter_all_named_volumes():
    diskinfo = plistlib.readPlistFromString(sh("diskutil list -plist"))
    for disk in diskinfo['AllDisksAndPartitions']:
        for part in disk['Partitions']:
            vn = part.get("VolumeName")
            if vn:
                yield vn

def sh(cmd):
    return Popen(cmd,shell=True,stdout=PIPE,stderr=PIPE).communicate()[0]

def debug(msg):
    if DEBUG:
        f = open ('/tmp/completedebug','a')
        f.write (str(msg) + '\n')
        f.close()

def get_disks(curr=''):
    if USE_CACHE and os.path.exists(cache):
        diskinfo = plistlib.readPlist(cache)
    else:
        diskinfo = plistlib.readPlistFromString(sh("diskutil list -plist"))
        if USE_CACHE:
            plistlib.writePlist(diskinfo,cache)
    if curr.startswith("/"):
        m = diskinfo["AllDisks"]
        m = ["/dev/"+d for d in m]
        v = diskinfo["VolumesFromDisks"]
        v = ["/Volumes/"+d for d in v]
        return m + v
    return list(iter_all_named_volumes()) + diskinfo['AllDisks']
    # return diskinfo['VolumesFromDisks'] + diskinfo['AllDisks']
    named_disk_ct = len(diskinfo['VolumesFromDisks'])
    opts = []
    for i,d in enumerate(diskinfo['WholeDisks']):
        o = "/dev/%s" % d
        if i < named_disk_ct:
            o += "(%s)" % diskinfo['VolumesFromDisks'][i].replace(' ','_')
        if curr:
            if o.startswith(curr):
                opts.append(o)
        else:
            opts.append(o)
    if len(opts) == 1 and '(' in opts[0]:
        opts[0] = opts[0].split('(')[0]
    debug ("disks:");debug(opts)
    return opts

def re_in(pat,l):
    r = re.compile(pat)
    contained = [x for x in l if r.search(x)]
    return len(contained)

def complete():
    """ note if compreply only gets one word it will fully complete"""
    verbs = """
            list
            info
            activity
            listFilesystems
            unmount
            umount
            unmountDisk
            eject
            mount
            mountDisk
            renameVolume
            enableJournal
            disableJournal
            enableOwnership
            disableOwnership
            verifyVolume
            repairVolume
            verifyPermissions
            repairPermissions
            eraseDisk
            eraseVolume
            reformat
            eraseOptical
            zeroDisk
            randomDisk
            secureErase
            partitionDisk
            resizeVolume
            splitPartition
            mergePartition
            """.split()
    verbs_for_device = """
            list
            info
            unmount
            umount
            unmountDisk
            eject
            mount
            mountDisk
            renameVolume
            enableJournal
            disableJournal
            enableOwnership
            disableOwnership
            verifyVolume
            repairVolume
            verifyPermissions
            repairPermissions
            eraseDisk
            eraseVolume
            reformat
            eraseOptical
            zeroDisk
            randomDisk
            secureErase
            partitionDisk
            resizeVolume
            splitPartition
            mergePartition
            """.split()
    device_final = """
            list
            info
            unmount
            umount
            unmountDisk
            eject
            mount
            mountDisk
            enableJournal
            disableJournal
            verifyVolume
            repairVolume
            verifyPermissions
            repairPermissions
            eraseDisk
            eraseVolume
            eraseOptical
            zeroDisk
            randomDisk
            secureErase
            """.split()
    filesystem_nicknames = (
        "free", "fat32",
        "hfsx", "jhfsx", "jhfs+",
        "NTFS")
    partition_types = ( "APM", "MBR", "GPT" )
    verb_options = {
            "list":('-plist', ),
            "info":('-plist', '-all', ),
            "listFilesystems":('-plist', ),
            "unmount":('force', ),
            "umount":('force', ),
            "unmountDisk":('force', ),
            "eject":( ),
            "mount":('readOnly', '-mountPoint', ),
            "mountDisk":( ),
            "renameVolume":('<name>', ),
            "enableJournal":( ),
            "disableJournal":('force', ),
            "verifyVolume":( ),
            "repairVolume":( ),
            "verifyPermissions":('-plist', ),
            "repairPermissions":('-plist', ),
            "eraseDisk": ('<name>', ) + partition_types,
            "eraseVolume": ('<name>', ),
            "eraseOptical":('quick', ),
            "zeroDisk":( ),
            "randomDisk":('<times>', ),
            "secureErase":( ),
            "partitionDisk":( ),
            "resizeVolume":( ),
            "splitPartition":( ),
            "mergePartition":( )
            }
    cwords = os.environ['COMP_WORDS'].split('\n')[1:]
    cword = int(os.environ['COMP_CWORD'])
    debug(cword)

    try:
        curr = cwords[cword-1]
    except IndexError:
        curr = ''
    debug("current: " + curr)
    if cword == 1:
        if os.path.exists(cache):
            os.remove(cache)
        opts = verbs
    elif cwords[0] in verbs:
        opts = []
        if cwords[0] in verbs_for_device:
            # if verb has device as last param - and dev is last word, exit
            #if cword != len(cwords) and '/dev' in cwords[-1]:
            #    sys.exit(0)
            #if not re_in('/dev',cwords) or '/dev' in curr:
            #    opts.extend(get_disks(curr))
            opts.extend(get_disks(cwords[-1]))
        opts.extend(verb_options[cwords[0]])
        if cwords[0] == "eraseDisk" or cwords[0] == "eraseVolume":
            opts.extend(iter_all_filesystem_personalities())
            opts.extend(filesystem_nicknames)
        opts = [x for x in opts if x not in cwords[:-2]]
        debug(opts)
        debug (cwords)
    sys.stdout.write('\n'.join(filter(lambda x: x.lower().startswith(curr.lower()), opts)))
    debug ("final |%s|" % ' '.join(filter(lambda x: x.startswith(curr), opts)))
    sys.exit(0)


def main():
    complete()
if __name__ == '__main__':
    main()

