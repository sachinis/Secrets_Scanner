import re
import os
import json
from concurrent.futures import ProcessPoolExecutor


class SecretsScanner(object):
    # SOURCE_ROOT_DIRECTORY = '../'
    # BLOCK_PATTERN_FILE = 'secrets-scanner/block_pattern_file.json'
    # ALLOW_PATTERN_FILE = 'secrets-scanner/allow_pattern_file.json'

    def __init__(self, allow_pattern_file, block_pattern_file, source_dir):
        self.file_list = []
        self.block_pattern = []
        self.allowed_string_pattern = []
        self.allowed_dirs = []
        self.allowed_files = []
        self.allowed_file_pattern = '(?!)'  # Default: matches nothing
        self.allowed_lines_pattern = []
        self.allowed_lines = []
        self.secrets_interim = []
        self.secrets = []
        self.changed_files = []
        self.scanned_file = []
        self.source_dir = os.path.realpath(source_dir)
        self.block_pattern_file = block_pattern_file
        self.allow_pattern_file = allow_pattern_file
        self.generate_patterns()

    def generate_patterns(self):
        block_file_path = os.path.abspath(self.block_pattern_file)
        allow_file_path = os.path.abspath(self.allow_pattern_file)

        try:
            with open(block_file_path) as f1:
                block_pattern = json.load(f1)
                self.block_pattern = block_pattern["Block_Pattern"]
        except:
            print("Error opening BLOCK Pattern File or parsing it")
            exit(1)

        try:
            self.read_allow_file(allow_file_path)
        except Exception as e:
            print(f'Error opening ALLOW Pattern File or parsing it: {e}')
            exit(1)

        # always ignore the contents of this project and the configuration files provided
        self.allowed_dirs.append(os.path.dirname(os.path.abspath(__file__)))
        self.allowed_files.append(allow_file_path)
        self.allowed_files.append(block_file_path)

    def read_allow_file(self, allow_file_path):
        with open(allow_file_path) as f2:
            allow_pattern = json.load(f2)
        if "Pattern_File_Version" in allow_pattern and allow_pattern["Pattern_File_Version"] == "v2":
            self.allowed_string_pattern = [pattern["pattern"] for pattern in allow_pattern["Allow_String_Pattern"]]
            self.allowed_dirs = [os.path.join(self.source_dir, dir["dir"]) for dir in allow_pattern["Allow_Dir"]]
            self.allowed_files = [os.path.join(self.source_dir, file["file"]) for file in allow_pattern["Allow_File"]]
            if "Allow_File_Pattern" in allow_pattern and len(allow_pattern["Allow_File_Pattern"]) > 0:
                self.allowed_file_pattern = '(?:%s)' % '|'.join([pattern["pattern"] for pattern in allow_pattern["Allow_File_Pattern"]])
            self.allowed_lines_pattern = allow_pattern["Allow_File_Line"]
            for pattern in self.allowed_lines_pattern:
                self.allowed_lines.append((os.path.join(self.source_dir, pattern["file"]), pattern["line"]))
        else: # version 1 of allow pattern file
            self.allowed_string_pattern = allow_pattern["Allow_String_Pattern"]
            self.allowed_dirs = [os.path.join(self.source_dir, dir) for dir in allow_pattern["Allow_Dir"]]
            self.allowed_files = [os.path.join(self.source_dir, file) for file in allow_pattern["Allow_File"]]
            if "Allow_File_Pattern" in allow_pattern and len(allow_pattern["Allow_File_Pattern"]) > 0:
                self.allowed_file_pattern = '(?:%s)' % '|'.join(allow_pattern["Allow_File_Pattern"])
            self.allowed_lines_pattern = allow_pattern["Allow_File_Line"]
            for pattern in self.allowed_lines_pattern:
                self.allowed_lines.append((os.path.join(self.source_dir, pattern.split(':$~')[0]), pattern.split(':$~')[1]))

    def full_scan(self):
        total_files = 0
        for dirpath1, dirs1, files1 in os.walk(self.source_dir):
            total_files += len(files1)
        for dirpath, dirs, files in os.walk(self.source_dir):
            # Logic to not scan whitelisted directories in allow_pattern_file.json
            for adir in self.allowed_dirs:
                if re.match(adir, dirpath):
                    print("Ignoring directory " + dirpath)
                    dirs[:] = []
                    files[:] = []
            for file in files:
                file_path = os.path.join(dirpath, file)
                # Logic to not scan whitelisted files in allow_pattern_file.json
                if file_path not in self.allowed_files and not re.match(self.allowed_file_pattern, file):
                    self.file_list.append(os.path.join(dirpath, file))
                else:
                    print("Ignoring file " + file_path)
        print()
        print(f'** Scanning for secrets in {len(self.file_list)} files out of {total_files} files. '
              f'Starting pattern matching now. **')
        print()
        with ProcessPoolExecutor(max_workers=8) as executor:
            results = executor.map(self.find_secrets, self.file_list)
        self.secrets_interim = [result for result in results if result is not None]
        for item1 in self.secrets_interim:
            for item in item1:
                self.secrets.append(item)
        return self.secrets

    # Finding secrets in files based on block patterns in block_pattern_file.json
    def find_secrets(self, filepath):
        filepath_secrets = []
        if filepath not in self.scanned_file:
            self.scanned_file.append(filepath)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for num, line in enumerate(f.readlines()):
                        for bpattern in self.block_pattern:
                            pattern = re.compile(bpattern)
                            matches = pattern.finditer(line)
                            for match in matches:
                                print(f'{match.group(0)} FOUND BY PATTERN {bpattern} '
                                      f'IN FILE {filepath} ON LINE {num+1}')
                                filepath_secrets.append((filepath, match.group(0), num + 1))
                if len(filepath_secrets) > 0:
                    return filepath_secrets
            except (UnicodeDecodeError, PermissionError, FileNotFoundError) as e:
                pass

    def purge_allowed_patterns(self, secrets):
        # Purging secrets matching allowed patterns in allow_pattern_file.json from secrets list
        for apattern in self.allowed_string_pattern:
            for index, item in reversed(list(enumerate(secrets))):
                if re.match(apattern, item[1], re.IGNORECASE):
                    print(f'Ignoring secret "{item[1]}" in file {item[0]} on line {item[2]} '
                        f'due to allowed pattern "{apattern}"')
                    del secrets[index]

        # Purging secrets found in whitelisted file lines from secrets list
        for value in self.allowed_lines:
            for index, item in reversed(list(enumerate(secrets))):
                if re.match(value[0], item[0]) and int(value[1]) == int(item[2]):
                    print(f'Ignoring secret {secrets[index][1]} in allowed line {value[1]} in file {value[0]}')
                    del secrets[index]
        return self.get_results(secrets)

    def get_results(self, secrets):
        if len(secrets) > 0:
            return secrets
        else:
            return None
