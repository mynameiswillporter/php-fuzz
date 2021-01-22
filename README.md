# php-fuzz
A Repository to enable simple fuzzing of PHP Source code. Based on this
[article](https://www.tripwire.com/state-of-security/vert/fuzzing-php-for-fun-and-profit/).

## Setup your ansible control server
The following steps will clone this repository, create a virtual environment,
and install ansible via pip.
```
apt-get install -y python3-venv
git clone https://github.com/mynameiswillporter/php-fuzz.git
cd php-fuzz
python3 -m venv venv
. venv/bin/activate
pip install ansible
```

## Use your ansible control server to install to localhost
Make sure you have your virtual environment with ansible activated and are in
this project's main directory.
```
ansible-playbook ansible/php-latest-afl-fuzz.yml -i localhost -e ansible_python_interpreter=/usr/bin/python
```


## Manual steps if you don't use ansible
```
# Based on https://www.tripwire.com/state-of-security/vert/fuzzing-php-for-fun-and-profit/

# Need git for latest php src
apt install git

# Fuzz in a screen session you dumb dumb
apt install screen

# Installing American Fuzzy Lop
apt install afl

# Installing PHP Source
git clone https://github.com/php/php-src.git
apt-get update
apt install -y pkg-config build-essential autoconf bison re2c libxml2-dev libsqlite3-dev
cd php-src
./buildconf

# Add lines for AFL optimization
LINENUM=$(grep -n "case PHP_MODE_CLI_DIRECT:" sapi/cli/php_cli.c | cut -f1 -d:)
LINENUM=$((LINENUM + 2))
awk -v n=$LINNUM -v s="\t\t\t__AFL_INIT();\n\t\t\twhile (__AFL_LOOP(100000))" 'NR == n {print s} {print}' sapi/cli/php_cli.c > sapi/cli/php_cli.c.new
mv sapi/cli/php_cli.c.new sapi/cli/php_cli.c

# Configure and make PHP
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure
AFL_USE_ASAN=1 make

# Create test cases
mkdir serialized_data && cd serialized_data
../sapi/cli/php -r 'echo serialize("a");' > string
../sapi/cli/php -r 'echo serialize(1);' > number
../sapi/cli/php -r 'echo serialize([1,2]);' > array_of_num
../sapi/cli/php -r 'echo serialize(["1","2"]);' > array_of_str
../sapi/cli/php -r 'echo serialize([["1","2"],["3","4"],[1,2]]);' > array_of_array
cd ..

# Everything is setup do the rest manually in screen
USE_ZEND_ALLOC=0 screen
afl-fuzz -i serialized_data -o basic_fuzz -m none -- ./sapi/cli/php -r 'unserialize(file_get_contents("php://stdin"));'

# Grepping for interesting crashes
for FILE in $(ls id*); do cat $FILE | ../../sapi/cli/php -r "unserialize(file_get_contents('php://stdin'));" 2>&1 | grep -E "SUMMARY|ERROR" | grep -v "LargeMmap" && echo $FILE; done
```
