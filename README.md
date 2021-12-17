# log4j_checker_beta

This script is used to perform a fast check if your server is possibly affected by CVE-2021-44228 (the log4j vulnerability).
It does not give a 100% proof, that you are not vulnerable, but it gives a hint if it is possible, that you could be vulnerable.

- scans files for occurrences of log4j
- checks for packages containing log4j and Solr ElasticSearch
- checks if Java is installed
- Analyzes JAR/WAR/EAR files
- Remediates Log4j 1.X by deleting JMSAppender class and 2.X by deleting JndiLookup on JAR files
- Option of checking hashes of .class files in archives

## Run with Remediation:

    wget https://raw.githubusercontent.com/commenciscloud/log4j_checker_beta/main/log4j_checker_beta.sh -q -O - |bash

## Run only Checker:

    wget https://raw.githubusercontent.com/commenciscloud/log4j_checker_beta/main/log4j_checker.sh -q -O - |bash


## Hash checking

The script can test .class files on the first level of JAR/WAR/EAR archives to see if they match with known sha256 hashes of vulnerable class files from log4j.  
You have to provide a download of plain text file with sha256 hashes in HEX format, one per line, everything after first <space> is ignored.
The URL can be placed in variable download_file. Otherwise this feature will not operate.
    
We did not include an actual URL, this exercise is left to the reader, as they say: 

The information Lunasec.io has put out about hashes of vulnerable binary Java .class files:

https://github.com/lunasec-io/lunasec/blob/master/tools/log4shell/constants/vulnerablehashes.go

Also see their blog: https://www.lunasec.io/docs/blog/log4j-zero-day-mitigation-guide/

## dependencies

The command `locate` has to to be installed, be sure to have locate up-to-date with:

    sudo updatedb
    
The command `unzip` also needs to be installed, to inspect the jar files.

## discussion

https://serverfault.com/questions/1086065/how-do-i-check-if-log4j-is-installed-on-my-server/1086132#1086132
