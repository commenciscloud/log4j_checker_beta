
#!/bin/bash

# source https://github.com/rubo77/log4j_checker_beta

# needs locate to be installed, be sure to be up-to-date with
# sudo updatedb

# Remediation functionality is developed by Commencis Cloud Team.
# https://www.commencis.com/commencis-cloud-transformation/

# regular expression, for which packages to scan for:
PACKAGES='solr\|elastic\|log4j'

export LANG=

RED="\033[0;31m"; GREEN="\033[32m"; YELLOW="\033[1;33m"; ENDCOLOR="\033[0m"
# if you don't want colored output, set the variables to empty strings:
# RED=""; GREEN=""; YELLOW=""; ENDCOLOR=""

function warning() {
  printf "${RED}[WARNING] %s${ENDCOLOR}\n" "$1" >&2
}

function information() {
  printf "${YELLOW}[INFO] %s${ENDCOLOR}\n" "$1"
}

function ok() {
  printf "${GREEN}[INFO] %s${ENDCOLOR}\n" "$1"
}

function locate_log4j() {
  if [ "$(command -v locate)" ]; then
    information "using locate, which could be using outdated data. besure to have called updatedb recently"
    locate log4j
  else
    find \
      /var /etc /usr /opt /lib* \
      -name "*log4j*" \
      2>&1 \
      | grep -v '^find:.* Permission denied$' \
      | grep -v '^find:.* No such file or directory$'   
  fi
}

function remediation_process() {
information "JAR files are collecting"
find \
  /var /etc /usr /opt /lib* \
  -name "*log4j*.jar" \
  -type f \
  2>&1 \
  | grep -v '^find:.* Permission denied$' \
  | grep -v '^find:.* No such file or directory$'  \
  | while read -r line ; do \
    if [[ $line == *"-1."* ]]; then
      if zip -qq -d $line */JMSAppender.class 2>&1 > /dev/null  ; then
        ok "$line remediated"
      else
        ok "Nothing to remediate on $line"
      fi 
    elif [[ $line == *"log4j-core"* ]]; then
        if  zip -qq -d $line org/apache/logging/log4j/core/lookup/JndiLookup.class 2>&1 > /dev/null ; then
          ok "$line remediated"
        else
          ok "Nothing to remediate on $line"
        fi
    fi
done
}

function find_class_files() {
  find /var /etc /usr /opt /lib* -type f\
   -name "*.jar" -o \
   -name "*.ear" -o \
   -name "*.war" -o \
   -name "*.properties" -o \
   -name "*.class" -o \
   -name "*.journal" \
  | xargs grep -i 'JMSAppend\|JndiLookup' 
}

function find_jar_files() {
  find \
    /var /etc /usr /opt /lib* \
    -name "*.jar" \
    -o -name "*.war" \
    -o -name "*.ear" \
    2>&1 \
    | grep -v '^find:.* Permission denied$' \
    | grep -v '^find:.* No such file or directory$'
}

if [ $USER != root ]; then
  warning "You have no root-rights. Not all files will be found."
fi

information "Looking for files containing log4j..."
OUTPUT="$(locate_log4j | grep -iv log4js | grep -v log4j_checker_beta)"
if [ "$OUTPUT" ]; then
  warning "Maybe vulnerable, those files contain the name:"
  printf "%s\n" "$OUTPUT"
else
  ok "No files containing log4j"
fi

information "Checking installed packages Solr ElasticSearch and packages containing log4j"
if [ "$(command -v yum)" ]; then
  # using yum
  OUTPUT="$(yum list installed | grep -i $PACKAGES | grep -iv log4js)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, yum installed packages:"
    printf "%s\n" "$OUTPUT"
  else
    ok "No yum packages found"
  fi
fi
if [ "$(command -v dpkg)" ]; then
  # using dpkg
  OUTPUT="$(dpkg -l | grep -i $PACKAGES | grep -iv log4js)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, dpkg installed packages:"
    printf "%s\n" "$OUTPUT"
  else
    ok "No dpkg packages found"
  fi
fi

information "Checking if Java is installed..."
JAVA="$(command -v java)"
if [ "$JAVA" ]; then
  warning "Java is installed"
  printf "     %s\n     %s\n" \
    "Java applications often bundle their libraries inside binary files," \
    "so there could be log4j in such applications."
else
  ok "Java is not installed"
fi

information "Analyzing JAR/WAR/EAR files..."
if [ "$(command -v unzip)" ]; then
  find_jar_files | while read -r jar_file; do
    unzip -l "$jar_file" 2> /dev/null \
      | grep -q -i "log4j" \
      && warning "$jar_file contains log4j files"
  done
else
  information "Cannot look for log4j inside JAR/WAR/EAR files (unzip not found)"
fi

information "Searching for  JMSAppend or JndiLookup in files..."
OUTPUT="$(find_class_files)"
if [ "$OUTPUT" ]; then
  warning "Maybe vulnerable, those files contain the name:"
  printf "$OUTPUT\n"
else
  ok  "JMSAppend or JndiLookup does not exists."
fi

information "Remediation Process..."
OUTPUT="$(remediation_process)"
if [ "$OUTPUT" ]; then
  printf "$OUTPUT"
else
  ok  "No vulnarable file found."
fi

echo
information "_________________________________________________"
if [ "$JAVA" == "" ]; then
  warning "Some apps bundle the vulnerable library in their own compiled package, so 'java' might not be installed but one such apps could still be vulnerable."
fi
echo
warning "This whole script is not 100% proof you are not vulnerable, but a strong hint"
echo

