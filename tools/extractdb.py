#!/usr/bin/env python3
import sys
import os
from zipfile_patched import ZipFile

FILENAME_BEGIN = b'APOSZexandtl'
DB_PASSWD = b'Z8wQh6o3'

CHOICE_PREFIX = 0
CHOICE_MIDDLE = 1
CHOICE_SUFFIX = 2

def decfilename(enc):
    prelen,midlen,suflen = 0,0,0
    for i in range(len(enc)):
        choice = ((i // 3) + (((i * 0xaaaaaaab) >> 0x20) & 0xfffffffe)) & 0xffffffff
        if i - choice == 1:
            midlen += 1
        elif i == choice:
            prelen += 1
        else:
            suflen += 1
    prefix = iter(enc[:prelen])
    middle = iter(enc[prelen:prelen+midlen])
    suffix = iter(enc[prelen+midlen:prelen+midlen+suflen])
    dec = bytearray()
    for i in range(len(enc)):
        choice = ((i // 3) + (((i * 0xaaaaaaab) >> 0x20) & 0xfffffffe)) & 0xffffffff
        if i - choice == 1:
            dec.append(next(middle))
        elif i == choice:
            dec.append(next(prefix))
        else:
            dec.append(next(suffix))
    finalname = dec[::-1]
    if not finalname.startswith(FILENAME_BEGIN):
        raise ValueError("Filename provided does not start with encryption prefix!")
    return bytes(finalname[len(FILENAME_BEGIN):])

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <Database> <Folder>")
        sys.exit(1)
    zipname = sys.argv[1]
    output = sys.argv[2]
    with ZipFile(zipname) as fp:
        fp.extractall(path=output, pwd=DB_PASSWD)
        for fname in os.listdir(output):
            os.rename(os.path.join(output, fname), os.path.join(output.encode(), decfilename(fname.encode())))

if __name__ == '__main__':
    main()
