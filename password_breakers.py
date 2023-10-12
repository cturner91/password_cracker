from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
import os


class PasswordCrackerBase:

    def __init__(self):
        self.chars = []
        self._length = 0

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
        

class BruteForcePasswordCracker(PasswordCrackerBase):

    def __init__(self):
        super().__init__()
        # for multi-processing, need a way to communicate with other processes 
        # to let them know if another process has found the solution
        self.stop_path = './stop.txt'

        if os.path.exists(self.stop_path):
            os.remove(self.stop_path)

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
        return os.path.exists(self.stop_path)

    def _write_stop(self, password=''):
        with open(self.stop_path, 'w') as f:
            f.write(password)

    def _remove_stop(self):
        return os.remove(self.stop_path)

    def crack_password(self, i=0, inc=1):
        guess = ''
        count = 0
        while guess != self.password:
            guess = self._get_guess(i)
            i += inc

            count += 1
            if count % 1000 == 0:
                if self._check_stop():
                    return

        self._write_stop(guess)
        return guess
    
    def crack_password_multiprocess(self, workers=1):
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for i in range(workers):
                pool.submit(self.crack_password, i, workers)

        with open(self.stop_path) as f:
            password = f.read()
        return password
