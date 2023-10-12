from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
import getpass
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

    def set_password(self, password=''):
        if not self.chars:
            raise ValueError('Must set some allowable characters first')

        if not password:
            password = getpass.getpass('Enter password: ')

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
        if self._check_stop():
            return os.remove(self.stop_path)


def calculate_word_stats(word):
    # a sumarised view of a password, without exposing what it actually is
    # we report this to the user after they find out their password strength
    count_lowers = len([char for char in word if char in 'abcdefghijklmnopqrstuvwxyz'])
    count_uppers = len([char for char in word if char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'])
    count_numbers = len([char for char in word if char in '0123456789'])
    char_counts = {}
    for char in word:
        if char in char_counts:
            char_counts[char] += 1
        else:
            char_counts[char] = 1

    repeats = {key: value for key, value in char_counts.items() if value > 1}

    return {
        'lowers': count_lowers,
        'uppers': count_uppers,
        'numbers': count_numbers,
        'repeats': repeats,
    }


def print_word_stats(word):
    stats = calculate_word_stats(word)
    if stats['lowers']:
        print(f'Password has {stats["lowers"]} lower-case character(s).')
    if stats['uppers']:
        print(f'Password has {stats["uppers"]} upper-case character(s).')
    if stats['numbers']:
        print(f'Password has {stats["numbers"]} number(s).')
    if stats['repeats']:
        print(f'Password has {len(stats["repeats"])} character(s) repeated at least once.')


class TimeMe:
    def __enter__(self):
        self.dt1 = datetime.utcnow()
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.dt2 = datetime.utcnow()
        self.time_elapsed = (self.dt2-self.dt1).total_seconds()


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
        self._remove_stop()
        guess = ''
        count = 0
        while guess != self.password:
            guess = self._get_guess(i)
            i += inc

            # multiprocessing early exit clause
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
        passwords = [password.strip().lower() for password in passwords if password]
        self.passwords = passwords

        # set up allowable substitutions
        self.substitutions = {char: [char, char.upper()] for char in list('abcdefghijklmnopqrstuvwxyz')}
        for char, sub in (
            ('a', '4'), ('e', '3'), ('i', '1'), ('o', '0'), ('s', '5'), ('z', '2'), 
        ):
            self.substitutions[char].append(sub)

        # allow any characters for passwords. Not really applicable to DictionaryCracker -> more of use for BruteForce
        # However we still validate password based on allowable chars (e.g. exclude emojis), so keep in
        self.add_lowers()
        self.add_uppers()
        self.add_numbers()
        self.add_symbols()

    def set_password(self, password=''):
        self._variations = []
        return super().set_password(password)

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

    def _generate_variations(self, word, idx=0, current=''):
        if idx == len(word):
            self._variations.append(current)
            return
        
        char = word[idx]

        if char in self.substitutions:
            for sub_char in self.substitutions[char]:
                self._generate_variations(word, idx + 1, current + sub_char)
        else:
            self._generate_variations(word, idx + 1, current + char)

    def crack_password(self, i=0, inc=1):
        self._remove_stop()
        count = 0
        for password in self.passwords[i::inc]:
            self._variations = []
            self._generate_variations(password)
            for variation in self._variations:
                
                # Add some trailing punctuation marks - very primitive method to inject symbols but better than nothing
                for trailing in ('', '!', '!!', '?'):
                    guess = f'{variation}{trailing}'
                    count += 1
                    if guess == self.password:
                        self._write_stop(guess)
                        self.check_count = count
                        return guess

                # multiprocessing early exit clause                    
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
