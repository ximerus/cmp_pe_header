__author__ = 'ximera'
__date__='30.10.2015'

import pefile
import sys
import os
from colors import *


def main():

    if len(sys.argv) < 2:
        usage(sys.argv[0])
        exit()

    path = sys.argv[1]
    if path == 0:
        usage(sys.argv[0])
        exit()

    files_count = len([name for name in os.listdir(path) if os.path.isfile(os.path.join(path, name))])
    if files_count != 0:
        sys.stdout.write("Total files in dir: %s\n" % str(files_count))
    else:
        sys.stdout.write("Folder is empty!\n")
        sys.exit(-1)
    files = os.listdir(path)
    i = 0
    while i < len(files)-1:
        if os.path.isfile(os.path.join(path, files[i])) and os.path.isfile(
                os.path.join(path, files[i + 1])) and is_pe_file(os.path.join(path, files[i])) and is_pe_file(
                os.path.join(path, files[i + 1])):
            sys.stdout.write(cyan("\n\nFile1:\t"+files[i]+"\tFile2:\t"+files[i+1]+"\n"))
            cmp_dos_headers_info(os.path.join(path, files[i]), os.path.join(path, files[i+1]))
            cmp_file_header(os.path.join(path, files[i]), os.path.join(path, files[i+1]))
            cmp_nt_header(os.path.join(path, files[i]), os.path.join(path, files[i+1]))
            cmp_optional_header(os.path.join(path, files[i]), os.path.join(path, files[i+1]))
            sys.stdout.write(magenta("*"*95))
        i += 1


def cmp_dos_headers_info(first_file, second_file):
    sys.stdout.write(magenta("="*40+">[DOS HEADER]<"+"="*41+"\n"))
    f_pe_file = pefile.PE(first_file)
    s_pe_file = pefile.PE(second_file)
    for key in s_pe_file.DOS_HEADER.__keys__:
        key_str = "".join(key)
        sys.stdout.write(blue("%30s" % key_str + ":\t"))
        if f_pe_file.DOS_HEADER.__dict__.__getitem__(key_str) == s_pe_file.DOS_HEADER.__dict__.__getitem__(key_str):
            if type(f_pe_file.DOS_HEADER.__dict__.__getitem__(key_str)) == str:
                sys.stdout.write(red("-"*50+"\n"))
            else:
                sys.stdout.write(red("{:<32}\t".format(hex(f_pe_file.DOS_HEADER.__dict__.__getitem__(key_str)))))
                sys.stdout.write(red("\t0x%x" % s_pe_file.DOS_HEADER.__dict__.__getitem__(key_str)+"\n"))
        else:
            if type(f_pe_file.DOS_HEADER.__dict__.__getitem__(key_str)) == str:
                sys.stdout.write(green("-"*50+"\n"))
            else:
                sys.stdout.write(green("{:<32}\t".format(hex(f_pe_file.DOS_HEADER.__dict__.__getitem__(key_str)))))
                sys.stdout.write(green("\t0x%x" % s_pe_file.DOS_HEADER.__dict__.__getitem__(key_str)+"\n"))


def cmp_file_header(first_file, second_file):
    sys.stdout.write(magenta("="*40+">[FILE HEADER]<"+"="*40+"\n"))
    f_pe_file = pefile.PE(first_file)
    s_pe_file = pefile.PE(second_file)
    for key in s_pe_file.FILE_HEADER.__keys__:
        key_str = "".join(key)
        sys.stdout.write(blue("%30s" % key_str + ":\t"))
        if f_pe_file.FILE_HEADER.__dict__.__getitem__(key_str) == s_pe_file.FILE_HEADER.__dict__.__getitem__(key_str):
            sys.stdout.write(red("{:<32}\t".format(hex(f_pe_file.FILE_HEADER.__dict__.__getitem__(key_str)))))
            sys.stdout.write(red("\t0x%x" % s_pe_file.FILE_HEADER.__dict__.__getitem__(key_str)+"\n"))
        else:
            sys.stdout.write(green("{:<32}\t".format(hex(f_pe_file.FILE_HEADER.__dict__.__getitem__(key_str)))))
            sys.stdout.write(green("\t0x%x" % s_pe_file.FILE_HEADER.__dict__.__getitem__(key_str)+"\n"))


def cmp_nt_header(first_file, second_file):
    sys.stdout.write(magenta("="*40+">[NT HEADER]<"+"="*42+"\n"))
    f_pe_file = pefile.PE(first_file)
    s_pe_file = pefile.PE(second_file)
    for key in f_pe_file.NT_HEADERS.__keys__:
        key_str = "".join(key)
        sys.stdout.write(blue("%30s" % key_str + ":\t"))
        if f_pe_file.NT_HEADERS.__dict__.__getitem__(key_str) == s_pe_file.NT_HEADERS.__dict__.__getitem__(key_str):
            sys.stdout.write(red("{:<32}\t".format(hex(f_pe_file.NT_HEADERS.__dict__.__getitem__(key_str)))))
            sys.stdout.write(red("\t0x%x" % s_pe_file.NT_HEADERS.__dict__.__getitem__(key_str)+"\n"))
        else:
            sys.stdout.write(green("{:<32}\t".format(hex(f_pe_file.NT_HEADERS.__dict__.__getitem__(key_str)))))
            sys.stdout.write(green("\t0x%x" % s_pe_file.NT_HEADERS.__dict__.__getitem__(key_str)+"\n"))


def cmp_optional_header(first_file, second_file):
    sys.stdout.write(magenta("="*38+">[OPTIONAL HEADER]<"+"="*38+"\n"))
    f_pe_file = pefile.PE(first_file)
    s_pe_file = pefile.PE(second_file)
    for key in f_pe_file.OPTIONAL_HEADER.__keys__:
        key_str = "".join(key)
        sys.stdout.write(blue("%30s" % key_str + ":\t"))
        if f_pe_file.OPTIONAL_HEADER.__dict__.__getitem__(key_str) == s_pe_file.OPTIONAL_HEADER.__dict__.__getitem__(key_str):
            sys.stdout.write(red("{:<32}\t".format(hex(f_pe_file.OPTIONAL_HEADER.__dict__.__getitem__(key_str)))))
            sys.stdout.write(red("\t0x%x" % s_pe_file.OPTIONAL_HEADER.__dict__.__getitem__(key_str)+"\n"))
        else:
            sys.stdout.write(green("{:<32}\t".format(hex(f_pe_file.OPTIONAL_HEADER.__dict__.__getitem__(key_str)))))
            sys.stdout.write(green("\t0x%x" % s_pe_file.OPTIONAL_HEADER.__dict__.__getitem__(key_str)+"\n"))


def is_pe_file(in_file):
    readed_file = open(in_file, 'r')
    if readed_file.read(2) == 'MZ':
        return 1
    else:
        return 0


def print_msg(code, msg):
    if code == -1:
        print red("[ERROR]\t" + msg)
    elif code == 1:
        print yellow("[WARNING]\t"+msg)
    else:
        print green("[INFO]\t" + msg)


def usage(module_name):
    print 'Usage: ' + module_name + " <folder_with_pe_files>"


if __name__ == '__main__':
    main()