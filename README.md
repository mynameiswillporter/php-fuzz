# php-fuzz
A Repository to enable simple fuzzing of PHP Source code. Based on this
[article](https://www.tripwire.com/state-of-security/vert/fuzzing-php-for-fun-and-profit/).

The ansible script in this repo will pull the PHP source, add the `__AFL_INIT();`
and `while (__AFL_LOOP(100000))` into `sapi/cli/php_cli.c` and make PHP with
these modifications.

These modifcations will allow fuzzing of php via `afl-fuzz` and `./sapi/cli/php`.

After setting up the server fuzzing should be as simple as:
1. Creating test cases
2. Running the fuzz command in a screen with `USE_ZEND_ALLOC=0` set

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

## Creating test cases
Test cases should be in the form of input that can be read from stdin into the
php function you want to fuzz.

In the article, `unserialize` is the targeted function. Therefore the test cases
are in the form of data that can serve as input to `unserialize`, namely output
from `serialize`.

So working the php-src directory, the following commands will create example
test cases that could be used to fuzz `unserialize`:

```
mkdir serialized_data && cd serialized_data
../sapi/cli/php -r 'echo serialize("a");' > string
../sapi/cli/php -r 'echo serialize(1);' > number
../sapi/cli/php -r 'echo serialize([1,2]);' > array_of_num
../sapi/cli/php -r 'echo serialize(["1","2"]);' > array_of_str
../sapi/cli/php -r 'echo serialize([["1","2"],["3","4"],[1,2]]);' > array_of_array
```

## Running the Fuzz
`USE_ZEND_ALLOC=0` must be set for the fuzzer to work properly. If you
run a screen via `USE_ZEND_ALLOC=0 screen` all of the fuzzing can be done in
that screen. The screen will also be neccesary since fuzzing will be long
running.

Then from the php-src directory, with the test cases saved in these
`serialized_data` directory, the following command will run the fuzz.

```
afl-fuzz -i serialized_data -o basic_fuzz -m none -- ./sapi/cli/php -r 'unserialize(file_get_contents("php://stdin"));'
```
