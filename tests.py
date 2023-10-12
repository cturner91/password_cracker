
import unittest

from password_breakers import BruteForcePasswordCracker


class TestBruteForce(unittest.TestCase):

    def test_guess(self):
        self.cracker = BruteForcePasswordCracker()
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
        self.cracker = BruteForcePasswordCracker()
        self.cracker.chars.extend(['a','b','c'])
        self.cracker._update_length()
        self.cracker.set_password('bacca')
        self.assertEqual(self.cracker.crack_password(), 'bacca')

    def test_break_password_multi(self):
        self.cracker = BruteForcePasswordCracker()
        self.cracker.chars.extend(['a','b','c'])
        self.cracker._update_length()
        self.cracker.set_password('bacca')
        self.assertEqual(self.cracker.crack_password_multiprocess(), 'bacca')
