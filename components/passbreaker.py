import hashlib
import argparse
import itertools
from multiprocessing import Pool


class PasswordCracker:
    def __init__(self, password_hash, wordlist_file, algorithm, salt=None, parallel=False, complexity_check=False):
        self.password_hash = password_hash
        self.wordlist_file = wordlist_file
        self.algorithm = algorithm
        self.salt = salt
        self.parallel = parallel
        self.complexity_check = complexity_check
        self.total_passwords = 0
        self.matched_password = None

    def crack_hash(self, word):
        if self.salt:
            word_with_salt = f'{self.salt}{word}'
        else:
            word_with_salt = word
        hashed_word = hashlib.new(self.algorithm, word_with_salt.encode()).hexdigest()
        if hashed_word == self.password_hash:
            self.matched_password = word
            return True
        return False

    def generate_passwords(self, min_length, max_length, character_set):
        passwords = []
        for length in range(min_length, max_length + 1):
            for combination in itertools.product(character_set, repeat=length):
                password = ''.join(combination)
                passwords.append(password)
        return passwords

    def evaluate_complexity(self, password):
        has_lowercase = False
        has_uppercase = False
        has_digit = False
        has_special = False

        for char in password:
            if char.islower():
                has_lowercase = True
            elif char.isupper():
                has_uppercase = True
            elif char.isdigit():
                has_digit = True
            else:
                has_special = True

        if len(password) >= 8 and has_lowercase and has_uppercase and has_digit and has_special:
            return True
        return False

    def crack_passwords(self, passwords):
        for password in passwords:
            self.total_passwords += 1
            if self.crack_hash(password):
                break

    def crack_passwords_parallel(self, passwords):
        pool = Pool()
        pool.map(self.crack_password, passwords)
        pool.close()

    def crack_password(self, password):
        if self.complexity_check and not self.evaluate_complexity(password):
            return
        if self.matched_password is None:
            if self.crack_hash(password):
                return

    def crack_passwords_with_wordlist(self):
        with open(self.wordlist_file, 'r', encoding="latin-1") as wordlist:
            passwords = wordlist.read().splitlines()
            if self.parallel:
                self.crack_passwords_parallel(passwords)
            else:
                self.crack_passwords(passwords)

    def crack_passwords_with_brute_force(self, min_length, max_length, character_set):
        passwords = self.generate_passwords(min_length, max_length, character_set)
        if self.parallel:
            self.crack_passwords_parallel(passwords)
        else:
            self.crack_passwords(passwords)

    def print_statistics(self):
        print(f"Total Number of Passwords Tried: {self.total_passwords}")
        if self.matched_password:
            print(f"Password Cracked! Password: {self.matched_password}")
        else:
            print("Password Failed.")


def main():
    parser = argparse.ArgumentParser(description='Password cracking source PassBreaker')
    parser.add_argument('password_hash', help='Password hash')
    parser.add_argument('wordlist_file', help='Wordlist File')
    parser.add_argument('--algorithm', choices=hashlib.algorithms_guaranteed, required=True, help='Hash algorithm')
    parser.add_argument('-s', '--salt', help='Salt Value')
    parser.add_argument('-p', '--parallel', action='store_true', help='Use parallel processing')
    parser.add_argument('-c', '--complexity', action='store_true', help='Check for password complexity')
    parser.add_argument('-b', '--brute-force', action='store_true', help='Perform a brute force attack')
    parser.add_argument('--min-length', type=int, default=1, help='Minimum password length for brute force attack')
    parser.add_argument('--max-length', type=int, default=6, help='Minimum password length for brute force attack')
    parser.add_argument('--character-set', default='abcdefghijklmnopqrstuvwxyz0123456789',
                        help='Character set for brute force attack')

    args = parser.parse_args()

    cracker = PasswordCracker(args.password_hash, args.wordlist_file, args.algorithm, args.salt, args.parallel, args.complexity)

    if args.brute_force:
        cracker.crack_passwords_with_brute_force(args.min_length, args.max_length, args.character_set)
    else:
        cracker.crack_passwords_with_wordlist()

    cracker.print_statistics()


if __name__ == '__main__':
    main()