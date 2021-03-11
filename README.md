# secrets-scanner

Secrets scanner scans your code for secrets based on secrets pattern files (block_pattern_file.json and allow_pattern_file.json).
'block_pattern_file.json' contains secrets patterns (regular expressions) to find secrets in the source code.
False positives are weeded out in the 'allow_pattern_file.json' file. The file contains patterns to whitelist files, directories, string patterns and lines in files so that secrets found in the white-lists are ignored.
 
**Dependency**:

The code in 'secrets-scanner' repo was written using python v3.8.5 but it should work fine with python versions 3.4 and above.

**Suggested usage**

The 'secrets-scanner' package is intended to be run as a job within the security stage in your pipeline. This job should ideally be run when developers push code to their branch. The passing of this job must be a pre-requsite for MR approval. If false-positives are found in the scan results of this job, then the false positives must be removed by including an appropriate allowed pattern.

**Script usage**

1. Clone the 'secrets-scanner' python package.

2. Commands : 

i) Type the below command for help : 

`python3 secrets-scanner --help`

ii) Including command-line arguments; you can use relative paths or absolute paths :

`python3 secrets-scanner -a '<Allowed-Pattern-FilePath>' -b '<Blocked-Pattern-FilePath>' -s '<Source-Code-Path>'`

                        OR
                        
`python3 secrets-scanner --apattern '<Allowed-Pattern-FilePath>' --bpattern '<Blocked-Pattern-FilePath>' --source_dir '<Source-Code-Path>'`

iii) With default command-line arguments (source_dir = '../', apattern = 'secrets-scanner/allow_pattern_file.json', bpattern = 'secrets-scanner/block_pattern_file.json') :

Create a directory named 'security' in the root directory of your product repo. Navigate to the 'security' directory and clone this repo (secrets-scanner repo). Replace the 'allow_pattern_file.json' in the 'security' directory with a custom one and run the following command from the 'security' directory:

`python3 secrets-scanner`




