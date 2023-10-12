from concurrent.futures import ProcessPoolExecutor
from itertools import combinations
import os


class PasswordCrackerBase:

    def __init__(self):
        self.chars = []
        self._length = 0

        # for multi-processing, need a way to communicate with other processes 
        # to let them know if another process has found the solution
        self.stop_path = './stop.txt'
        if os.path.exists(self.stop_path):
            os.remove(self.stop_path)

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

    def set_password(self, password):
        if not self.chars:
            raise ValueError('Must set some allowable characters first')

        for letter in password:
            if letter not in self.chars:
                raise ValueError(f'Character {letter} not allowed')

        self.password = password
        
    def _check_stop(self):
        return os.path.exists(self.stop_path)

    def _write_stop(self, password=''):
        with open(self.stop_path, 'w') as f:
            f.write(password)

    def _remove_stop(self):
        return os.remove(self.stop_path)


class BruteForcePasswordCracker(PasswordCrackerBase):

    def _get_guess(self, i):
        idxs = []
        while i >= self._length:
            idxs.append(i % self._length)
            i = int(i / self._length) - 1
        idxs.append(i % self._length)
        output = ''.join([self.chars[idx] for idx in idxs])
        return output

    def crack_password(self, i=0, inc=1):
        guess = ''
        count = 0
        while guess != self.password:
            guess = self._get_guess(i)
            i += inc

            count += 1
            if count % 1000 == 0:
                if self._check_stop():
                    self.check_count = count
                    return

        self._write_stop(guess)
        self.check_count = count
        return guess
    
    def crack_password_multiprocess(self, workers=1):
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for i in range(workers):
                pool.submit(self.crack_password, i, workers)

        with open(self.stop_path) as f:
            password = f.read()
        return password


class DictionaryPasswordCracker(PasswordCrackerBase):

    def __init__(self, passwords_path='./passwords.txt'):
        super().__init__()
        with open(passwords_path) as f:
            passwords = f.read().split('\n')[1:]
        passwords = [password.strip() for password in passwords if password]
        self.passwords = passwords

        self.substitutions = {char: [char.upper()] for char in list('abcdefghijklmnopqrstuvwxyz')}
        for char, sub in (
            ('a', '4'), ('e', '3'), ('i', '1'), ('o', '0'), ('s', 'S'),
        ):
            self.substitutions[char].append(sub)

    def _get_idxs(self, string, char):
        return [i for i,ichar in enumerate(string) if ichar==char]
    
    def _get_combinations(self, items, length=0):
        all_combinations = []
        lengths = range(1, len(items) + 1) if length == 0 else [length]
        for r in lengths:
            all_combinations.extend(combinations(items, r))
        return all_combinations
    
    @staticmethod
    def _replace(string, idx, char):
        if idx == len(string)-1:
            return f'{string[:-1]}{char}'
        elif idx == 0:
            return f'{char}{string[1:]}'
        else:
            return f'{string[:idx]}{char}{string[idx+1:]}'
    
    def _replace_all(self, string, idxs, char):
        for idx in idxs:
            string = self._replace(string, idx, char)
        return string

    def _get_variations(self, password):
        yield password
        for char, subs in self.substitutions.items():
            idxs = self._get_idxs(password, char)
            if idxs:
                combis = self._get_combinations(idxs)
                for combi in combis:
                    for sub in subs:
                        new_password = self._replace_all(password, combi, sub)
                        yield new_password

    def crack_password(self, i=0, inc=1):
        count = 0
        for password in self.passwords[i::inc]:
            for variation in self._get_variations(password):
                count += 1
                if variation == self.password:
                    self._write_stop(variation)
                    self.check_count = count
                    return variation
                
                if count % 1000 == 0:
                    if self._check_stop():
                        self.check_count = count
                        return

    def crack_password_multiprocess(self, workers=1):
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for i in range(workers):
                pool.submit(self.crack_password, i, workers)

        with open(self.stop_path) as f:
            password = f.read()
        return password
