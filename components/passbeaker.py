import hashlib
import itertools
from multiprocessing import Pool
from rich.progress import Progress
from rich import print
from rich.panel import Panel
from rich.console import Group
from rich.align import Align
from rich import box


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
        self.progress = Progress()
        self.total_attempts = 0

    def crack_hash(self, word):
        word_with_salt = f'{self.salt}{word}' if self.salt else word
        hashed_word = hashlib.new(self.algorithm, word_with_salt.encode()).hexdigest()
        if hashed_word == self.password_hash:
            self.matched_password = word
            return True
        return False

    def generate_passwords(self, min_length, max_length, character_set):
        for length in range(min_length, max_length + 1):
            for combination in itertools.product(character_set, repeat=length):
                yield ''.join(combination)

    def evaluate_complexity(self, password):
        return (
            len(password) >= 8 and
            any(char.islower() for char in password) and
            any(char.isupper() for char in password) and
            any(char.isdigit() for char in password) and
            any(not char.isalnum() for char in password)
        )

    def crack_password(self, password):
        if self.complexity_check and not self.evaluate_complexity(password):
            return
        if self.crack_hash(password):
            self.total_passwords += 1
            return password
        with self.progress:
            self.progress.advance(self.task_id)

    def crack_passwords_parallel(self, passwords):
        with Pool() as pool, self.progress:
            self.total_attempts = len(passwords)
            self.task_id = self.progress.add_task("Cracking...", total=self.total_attempts)

            for result in pool.imap_unordered(self.crack_password, passwords):
                if result:
                    self.matched_password = result
                    break

            self.progress.update(self.task_id, completed=self.total_attempts)

    def crack_passwords(self, passwords):
        with self.progress:
            self.total_attempts = len(passwords)
            self.task_id = self.progress.add_task("Cracking...", total=self.total_attempts)

            for password in passwords:
                self.total_passwords += 1
                if self.crack_hash(password):
                    break

            self.progress.update(self.task_id, completed=self.total_attempts)

    def process_passwords(self, passwords):
        if self.parallel:
            self.crack_passwords_parallel(passwords)
        else:
            self.crack_passwords(passwords)

    def crack_passwords_with_wordlist(self):
        with open(self.wordlist_file, 'r', encoding="latin-1") as wordlist:
            self.process_passwords(wordlist.read().splitlines())

    def crack_passwords_with_brute_force(self, min_length, max_length, character_set):
        self.process_passwords(self.generate_passwords(min_length, max_length, character_set))

    def print_statistics(self):
        msg = f"Password Cracked! Password: {self.matched_password}" if self.matched_password else "Password Cracking Failed"
        message_panel = Panel(
            Align.center(
                Group("\n", Align.center(msg)),
                vertical="middle",
            ),
            box=box.ROUNDED,
            padding=(1, 2),
            title="[b red]The GVA Password Cracker",
            border_style="blue",
        )
        print(message_panel)
