
import unittest

from password_breakers import BruteForcePasswordCracker, DictionaryPasswordCracker, calculate_word_stats


# tests are not exhaustive, or particularly extensive. Just testing the key bits to make sure it works.

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


class TestDictionary(unittest.TestCase):

    def setUp(self):
        self.cracker = DictionaryPasswordCracker()

    def test_get_idxs(self):
        self.assertEqual([0, 2, 4], self.cracker._get_idxs('ababa', 'a'))
        self.assertEqual([1, 3], self.cracker._get_idxs('ababa', 'b'))

        self.assertEqual([1], self.cracker._get_idxs('ab', 'b'))

        self.assertEqual([], self.cracker._get_idxs('ababa', 'c'))

    def test_get_combinations(self):
        combis = self.cracker._get_combinations([1, 2, 3])
        for expected in (
            (1, ), (2, ), (3, ),
            (1, 2), (1, 3), (2, 3),
            (1, 2, 3)
        ):
            self.assertIn(expected, combis)

    def test_get_combinations_fixed_length(self):
        combis = self.cracker._get_combinations([1, 2, 3], 2)
        for expected in (
            (1, 2), (1, 3), (2, 3),
        ):
            self.assertIn(expected, combis)

    def test_replace(self):
        self.assertEqual('abz', self.cracker._replace('abc', 2, 'z'))
        self.assertEqual('zbc', self.cracker._replace('abc', 0, 'z'))
        self.assertEqual('azc', self.cracker._replace('abc', 1, 'z'))

    def test_replace_all(self):
        self.assertEqual('zzz', self.cracker._replace_all('abc', [0, 1, 2], 'z'))

    def test_generate_variations(self):
        password = 'ababa'
        self.cracker.substitutions = {'b': ['b', 'c']}
        self.cracker._variations = []
        self.cracker._generate_variations(password)

        for expected in (
            'ababa', 'acaba', 'abaca', 'acaca'
        ):
            self.assertIn(expected, self.cracker._variations)

    def test_generate_variations2(self):
        password = 'abcabc'
        self.cracker.substitutions = {'a': ['a', 'z', 'y']}
        self.cracker._variations = []
        self.cracker._generate_variations(password)

        for expected in (
            'abcabc', 
            'zbcabc', 'abczbc', 'zbczbc',
            'ybcabc', 'abcybc', 'ybcybc',
            #'zbcybc', 'ybczbc',  # code does not do combinations of substitutions (yet)
        ):
            self.assertIn(expected, self.cracker._variations)

    def test_crack_password(self):
        self.cracker.add_lowers()
        self.cracker.add_uppers()
        self.cracker.add_numbers()
        self.cracker.set_password('P4ssw0rd')  # 'password' with P, a and 0 substituted
        self.assertEqual(self.cracker.crack_password(), 'P4ssw0rd')

        self.cracker.set_password('Ch3Ls3a')  # Chelsea with subsitutions and capitalisations
        self.assertEqual(self.cracker.crack_password(), 'Ch3Ls3a')

    def test_crack_password_multiprocessing(self):
        self.cracker.add_lowers()
        self.cracker.add_uppers()
        self.cracker.add_numbers()
        self.cracker.set_password('P4ssw0rd')  # 'password' with P, a and 0 substituted
        self.assertEqual(self.cracker.crack_password_multiprocess(), 'P4ssw0rd')


class TestWordStats(unittest.TestCase):

    def test_stats(self):
        self.assertDictEqual(calculate_word_stats('password'), {
            'lowers': 8,
            'uppers': 0,
            'numbers': 0,
            'repeats': {'s': 2},
        })

        self.assertDictEqual(calculate_word_stats('Ch3lS3a'), {
            'lowers': 3,
            'uppers': 2,
            'numbers': 2,
            'repeats': {'3': 2},
        })


if __name__ == '__main__':
    unittest.main()
