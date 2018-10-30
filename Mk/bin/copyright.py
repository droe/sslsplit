#!/usr/bin/env python3
# vim: set ft=python list et ts=8 sts=4 sw=4:

# Update the copyright headers in all source files passed on the command line.
# The copyright headers are comments at the beginning of lines that are
# marked by a dash immediately at the start of the comment.
# The entire copyright header is replaced by the copyright in LICENSE, with the
# exception of contributor's additional Copyright lines, which are kept intact
# as found in each source file.

import sys
import os

MAIN_NAME = 'Daniel Roethlisberger'
MAIN_EMAIL = 'daniel@roe.ch'
TITLE = ('SSLsplit - transparent SSL/TLS interception\n'
         'https://www.roe.ch/SSLsplit\n\n')

class Language:
    def __init__(self, begin, each, end):
        self.begin = begin
        self.each = each
        self.end = end

    def is_end(self, line):
        if self.end != None:
            return line.startswith(self.end)
        else:
            return not line.startswith(self.each)

languages = []
languages.append(Language('/*-',   ' *',   ' */'))  # c
languages.append(Language('#-',    '#',    None))   # scripts and make files
languages.append(Language('.\\"-', '.\\"', None))   # troff


def split_before(s, delimiter):
    s1, s2 = s.split(delimiter, 1)
    return s1, delimiter + s2

def commentline(prefix, line):
    if len(line) > 0:
        return prefix + ' ' + line + '\n'
    return prefix + '\n'

def license(outfile, language, contribrights=''):
    with open('LICENSE', 'r') as f:
        license = f.read()
    header, rest = split_before(license, 'Copyright')
    copyright, legalese = split_before(rest, 'All rights reserved')
    copyright = copyright.replace('and contributors', '<%s>' % MAIN_EMAIL)
    text = TITLE + copyright + contribrights + legalese
    outfile.write('%s\n' % language.begin)
    for line in text.splitlines():
        outfile.write(commentline(language.each, line))

def mangle(outfile, infile):
    contribs = []
    language = None
    have_first = False
    have_header = False
    for line in infile:
        if have_header:
            outfile.write(line)
        elif have_first:
            if language.is_end(line):
                license(outfile, language, ''.join(contribs))
                outfile.write(line)
                have_header = True
            elif 'Copyright' in line and not MAIN_NAME in line:
                prefix, copyright = split_before(line, 'Copyright')
                contribs.append(copyright)
        else:
            for lang in languages:
                if line.startswith(lang.begin):
                    language = lang
                    break
            if language == None:
                outfile.write(line)
                continue
            have_first = True

for fn in sys.argv[1:]:
    with open(fn, 'r') as infile:
        with open(fn + '~', 'w') as outfile:
            mode = os.fstat(infile.fileno()).st_mode
            os.fchmod(outfile.fileno(), mode)
            mangle(outfile, infile)
    os.rename(fn + '~', fn)

