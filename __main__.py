import os
import time
import argparse
from SecretsScanner import SecretsScanner

t1 = time.perf_counter()
parser = argparse.ArgumentParser(
    description="Pattern based secrets scanner",
    epilog='''python3 secrets-scanner -a <Allowed-Pattern-File> -b <Blocked-Pattern-File> -s <Source-Code-Path> '''
)

home_dir = os.path.dirname(os.path.abspath(__file__))

parser.add_argument('-a', '--apattern', help='Include absolute or relative path for allow_pattern_file.json',
                    action='store', default=home_dir + '/allow_pattern_file.json', required=False)
parser.add_argument('-b', '--bpattern', help='Include absolute or relative path for block_pattern_file.json',
                    action='store', default=home_dir + '/block_pattern_file.json',  required=False)
parser.add_argument('-s', '--source_dir', help='Include absolute or relative path of source code',
                    action='store', default=home_dir + '/../', required=False)
args = parser.parse_args()

obj = SecretsScanner(args.apattern, args.bpattern, args.source_dir)
print('-' * 65)
print(f'Starting full scan and finding secrets based on block patterns')
print('-'* 65)
secrets = obj.full_scan()
print('-' * 65)
print(f'Starting purge of allowed patterns')
print('-' * 65)
if secrets is not None:
    results = obj.purge_allowed_patterns(secrets)
else:
    results = None

if results:
    print('-' * 65)
    print(f'Final result(s) : Found {len(results)} secrets. They are listed below:')
    print('-' * 65)
    for index, (filename, text, line_num) in enumerate(results):
        msg = f'~~~~ {index+1} - Secret "{text}" found in "{filename}" in line number : {line_num} ~~~~'
        print(msg)
    t2 = time.perf_counter()
    print()
    print(f'Time taken for the script to complete execution = {round((t2 - t1),2)} second(s)')
    exit(1)
else:
    print('No secrets were found')
    t2 = time.perf_counter()
    print()
    print(f'Time taken for the script to complete execution = {round((t2 - t1),2)} second(s)')
    exit(0)
