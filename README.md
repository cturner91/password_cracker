# Password Breaker

Some python-based methods to try to break passwords.

There are two main approaches:

* **Dictionary-based** - Take a number of standard passwords / words and generate all combinations using usual substitutions for characters e.g. 'e' could be 'E' or '3'. So a password based on 'chelsea' could be any of 'CH3LS3A', 'Ch3ls3a', 'chel5EA' etc.

* **Brute Force** - Using a given list of allowable characters, try every possible combination e.g. if the allowable characters were just the digits 0-9, it would try 0-9, then 10-99, then 100-999 etc.

## Testing

The testing is a bit sparse. The code is by no means fully-tested, but the key elements are tested. This can be verified by running `python tests.py`.

## Try it yourself

Run `python password_strength_tester.py` and enter a password (preferably a weak one, unless you're prepared to wait a while). When the password gets cracked, it reports on how long it took to crack and how many variations were attempted before it was successfully cracked.

As an example:
* Results for password = 'password':
  * 0.003993 seconds taken, 996 variations checked
  * Password has 8 lower-case character(s).
  * Password has 1 character(s) repeated at least once.

* Results for password = 'Chel53A':
  * 0.107334 seconds taken, 260349 variations checked
  * Password has 3 lower-case character(s).
  * Password has 2 upper-case character(s).
  * Password has 2 number(s).

## Multi-processing

All solver methods are capable of multiprocessing - just run the `crack_password_multiprocess()` method with the number of concurrent processes as an input argument.
