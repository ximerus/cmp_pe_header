__author__ = 'ximera'
__date__='30.10.2015'

import pefile
import sys
import os


def main():
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


# put here your code

if __name__ == '__main__':
    main()