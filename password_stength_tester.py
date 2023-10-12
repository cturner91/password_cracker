from password_breakers import BruteForcePasswordCracker, DictionaryPasswordCracker, TimeMe, print_word_stats


if __name__ == '__main__':
    dc = DictionaryPasswordCracker()
    dc.set_password()

    with TimeMe() as timer:
        cracked = dc.crack_password()

    if cracked:
        print(f'{timer.time_elapsed} seconds taken, {dc.check_count} variations checked')
        print_word_stats(cracked)
    else:
        print(f'Dictionary attack failed in {timer.time_elapsed} seconds, resorting to brute force...')
        bf = BruteForcePasswordCracker()
        bf.add_lowers()
        bf.add_uppers()
        bf.add_numbers()
        bf.add_symbols()
        bf.set_password(dc.password)

        with TimeMe() as timer:
            cracked = bf.crack_password()
        print(f'{timer.time_elapsed} seconds taken, {bf.check_count} variations checked')
        print_word_stats(cracked)
