from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
import os


class PasswordCracker:

    def __init__(self):
        self.chars = []
        self.words = []
        self.password = ''
        self._length = 0
        self.path = './stop.txt'

        if os.path.exists(self.path):
            os.remove(self.path)

    def _update_length(self):
        self._length = len(self.chars)

    def add_char(self, char):
        self.chars.append(char)
        self._update_length()

    def add_lowers(self):
        self.chars.extend(list('abcdefghijklmnopqrstuvwxyz'))
        self._update_length()

    def add_uppers(self):
        self.chars.extend(list('ABCDEFGHIJKLMNOPQRSTUVWXYZ'))
        self._update_length()

    def add_numbers(self):
        self.chars.extend(list('0123456789'))
        self._update_length()

    def add_symbols(self):
        self.chars.extend(list('!@£$%^&*()€#,./;\'\\[]{}:"|?><'))
        self._update_length()

    # def load_dictionary(self, path='~/Desktop/dictionary.csv'):
    #     with open(path) as file:
    #         self.words = file.read().split(',')
        
    def set_password(self, password):
        if not self.chars:
            raise ValueError('Must set some allowable characters first')

        for letter in password:
            if letter not in self.chars:
                raise ValueError(f'Character {letter} not allowed')

        self.password = password

    def _get_guess(self, i):
        idxs = []
        while i >= self._length:
            idxs.append(i % self._length)
            i = int(i / self._length) - 1
        idxs.append(i % self._length)
        output = ''.join([self.chars[idx] for idx in idxs])
        return output
    
    def _check_stop(self):
        return os.path.exists(self.path)

    def _write_stop(self, password=''):
        with open(self.path, 'w') as f:
            f.write(password)

    def _remove_stop(self):
        return os.remove(self.path)

    def break_password(self, i=0, inc=1):
        guess = ''
        count = 0
        while guess != self.password:
            guess = self._get_guess(i)
            i += inc

            count += 1
            if count % 100 == 0:
                if self._check_stop():
                    return

        self._write_stop(guess)
        return guess
    
    def break_password_multiprocess(self, workers=1):
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for i in range(workers):
                pool.submit(self.break_password, i, workers)

        with open(self.path) as f:
            password = f.read()
        return password


import unittest

class TestBruteForce(unittest.TestCase):

    def test_guess(self):
        self.cracker = PasswordCracker()
        self.cracker.chars.extend(['a','b','c'])
        self.cracker._update_length()

        expected = (
            'a', 'b', 'c', 'aa', 'ab', 'ac', 'ba', 'bb', 'bc', 'ca', 'cb', 'cc',
            'aaa', 'aab', 'aac', 'aba', 'abb', 'abc', 'aca', 'acb', 'acc', 
            'baa', 'bab', 'bac', 'bba', 'bbb', 'bbc', 'bca', 'bcb', 'bcc', 
            'caa', 'cab', 'cac', 'cba', 'cbb', 'cbc', 'cca', 'ccb', 'ccc',
        )

        results = [self.cracker._get_guess(i) for i in range(len(expected))]
        for result in results:
            self.assertIn(result, expected)

    def test_break_password(self):
        self.cracker = PasswordCracker()
        self.cracker.chars.extend(['a','b','c'])
        self.cracker._update_length()
        self.cracker.set_password('bacca')
        self.assertEqual(self.cracker.break_password(), 'bacca')

    def test_break_password_multi(self):
        self.cracker = PasswordCracker()
        self.cracker.chars.extend(['a','b','c'])
        self.cracker._update_length()
        self.cracker.set_password('bacca')
        self.assertEqual(self.cracker.break_password_multiprocess(), 'bacca')


def run(password, workers=0):
    cracker = PasswordCracker()
    # cracker.add_lowers()
    cracker.add_numbers()
    cracker.set_password(password)

    dt1 = datetime.utcnow()
    if workers == 0:
        cracked = cracker.break_password()
    else:
        cracked = cracker.break_password_multiprocess(4)
    dt2 = datetime.utcnow()
    print(password, cracked, (dt2-dt1).total_seconds())

    cracker._remove_stop()


if __name__ == '__main__':
    # unittest.main()
    # run('31031991')
    run('31031991', 4)

