from datetime import datetime

from password_breakers import BruteForcePasswordCracker, DictionaryPasswordCracker, TimeMe


if __name__ == '__main__':
    # Note: for BruteForcePassword bf, 4 chars takes 1s, and every additional char takes ~30x longer

    dc = DictionaryPasswordCracker()
    dc.add_lowers()
    dc.add_uppers()
    dc.add_numbers()
    dc.set_password('Ch3Ls3A')

    with TimeMe() as timer:
        cracked = dc.crack_password()

    if cracked:
        print(f'{timer.time_elapsed} seconds taken, {dc.check_count} variations checked')
    else:
        print('Dictionary attack failed, resorting to brute force...')
        bf = BruteForcePasswordCracker()
        bf.add_lowers()
        bf.add_uppers()
        bf.add_numbers()
        bf.set_password(dc.password)

        with TimeMe() as timer:
            cracked = bf.crack_password()
        print(f'{timer.time_elapsed} seconds taken, {bf.check_count} variations checked')
