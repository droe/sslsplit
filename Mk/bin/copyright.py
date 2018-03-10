#!/usr/bin/env python3
# vim: set ft=python list et ts=8 sts=4 sw=4:

import sys
import os

def commentline(prefix, line):
    if len(line) > 0:
        return prefix + ' ' + line + '\n'
    return prefix + '\n'

def license(outfile, filetype):
    with open('LICENSE', 'r') as f:
        # skip title
        f.readline()
        f.readline()
        text = f.read()
    text = ('SSLsplit - transparent SSL/TLS interception\n'
            'https://www.roe.ch/SSLsplit\n\n') + text.replace(
                    'and contributors', '<daniel@roe.ch>')
    lines = text.splitlines()
    if filetype == 'c':
        outfile.write('/*-\n')
        for line in lines:
            outfile.write(commentline(' *', line))
    elif filetype == 'script':
        outfile.write('#-\n')
        for line in lines:
            outfile.write(commentline('#', line))
    elif filetype == 'man':
        outfile.write('.\\"-\n')
        for line in lines:
            outfile.write(commentline('.\\"', line))
    else:
        raise RuntimeError()

def mangle(outfile, infile):
    have_first = False
    have_header = False
    for line in infile:
        if have_header:
            outfile.write(line)
        elif have_first:
            if (filetype == 'c' and line.startswith(' */')) or \
               (filetype == 'script' and not line.startswith('#')) or \
               (filetype == 'man' and not line.startswith('.\\"')):
                outfile.write(line)
                have_header = True
        else:
            if line.startswith('/*-'):
                filetype = 'c'
            elif line.startswith('#-'):
                filetype = 'script'
            elif line.startswith('.\\"-'):
                filetype = 'man'
            else:
                outfile.write(line)
                continue
            license(outfile, filetype)
            have_first = True

for fn in sys.argv[1:]:
    with open(fn, 'r') as infile:
        with open(fn + '~', 'w') as outfile:
            mangle(outfile, infile)
    os.rename(fn + '~', fn)

