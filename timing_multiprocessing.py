from datetime import datetime

from password_breaker import BruteForcePasswordCracker


def run(password, workers=0):
    cracker = BruteForcePasswordCracker()
    # cracker.add_lowers()
    cracker.add_numbers()
    cracker.set_password(password)

    dt1 = datetime.utcnow()
    if workers == 0:
        cracked = cracker.crack_password()
    else:
        cracked = cracker.crack_password_multiprocess(4)
    dt2 = datetime.utcnow()
    print(password, cracked, (dt2-dt1).total_seconds())

    cracker._remove_stop()


if __name__ == '__main__':
    # unittest.main()
    run('3131991')
    run('3131991', 4)