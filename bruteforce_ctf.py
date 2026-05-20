import itertools
import hashlib
import concurrent.futures
import multiprocessing
import sys
import time
import threading
import argparse


class Spinner:
    """A simple command-line spinner with an elapsed timer to show progress."""
    def __init__(self, message="[*] Brute-forcing in progress"):
        self.spinner_cycle = itertools.cycle(['|', '/', '-', '\\'])
        self.stop_running = threading.Event()
        self.thread = threading.Thread(target=self.spin, daemon=True)
        self.message = message
        self.start_time = None

    def spin(self):
        while not self.stop_running.is_set():
            elapsed = int(time.time() - self.start_time)
            sys.stdout.write(f'\r{self.message} {next(self.spinner_cycle)} [{elapsed}s]')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * (len(self.message) + 20) + '\r')
        sys.stdout.flush()

    def start(self):
        self.start_time = time.time()
        self.thread.start()

    def stop(self):
        self.stop_running.set()
        self.thread.join()


class PasswordMutator:
    def __init__(self):
        self.common_subs = {
            'a': ['a', '4', '@'], 'A': ['A', '4', '@'],
            'e': ['e', '3'], 'E': ['E', '3'],
            'i': ['i', '1', '!'], 'I': ['I', '1', '!'],
            'o': ['o', '0'], 'O': ['O', '0'],
            's': ['s', '5', '$'], 'S': ['S', '5', '$'],
            't': ['t', '7'], 'T': ['T', '7'],
            'b': ['b', '8'], 'B': ['B', '8'],
            'g': ['g', '9'], 'G': ['G', '9']
        }
        # Symbols that can wrap the password (prefix / suffix)
        self.terminators = ['', '!', '?', '@', '#']
        # Numeric suffixes commonly appended to passwords (birth years, lucky numbers, etc.)
        self.num_suffixes = ['', '1', '13', '90', '1990', '123', '2024']

    def variant_generator(self, word):
        """Generates variants with leetspeak substitutions and common affixes."""
        word = word.strip()
        if not word:
            return

        grids = [self.common_subs.get(char, [char]) for char in word]

        for base in itertools.product(*grids):
            v = ''.join(base)
            for term1 in self.terminators:
                for num in self.num_suffixes:
                    for term2 in self.terminators:
                        yield term1 + v + num + term2


def _generate_root_words(base_words):
    """Generator that lazily yields 1-, 2-, and 3-word combinations without duplicates."""
    seen = set()

    def emit(w):
        if w not in seen:
            seen.add(w)
            return True
        return False

    for w in base_words:
        if emit(w): yield w
        cap = w.capitalize()
        if emit(cap): yield cap

    for w1, w2 in itertools.product(base_words, repeat=2):
        for combo in (w1 + w2, w1.capitalize() + w2.capitalize()):
            if emit(combo): yield combo

    for w1, w2, w3 in itertools.product(base_words, repeat=3):
        for combo in (w1 + w2 + w3, w1.capitalize() + w2.capitalize() + w3.capitalize()):
            if emit(combo): yield combo


def check_batch(variants_batch, target_hash):
    """Checks a batch of generated passwords against the target hash."""
    for password in variants_batch:
        if hashlib.sha256(password.encode()).hexdigest() == target_hash:
            return password
    return None


def execute_bruteforce(dict_file, target_hash):
    num_cores = multiprocessing.cpu_count()
    print(f"\n--- Initializing Brute-Force Workers: {num_cores} cores ---")

    try:
        with open(dict_file, 'r', encoding='utf-8') as f:
            base_words = [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Dictionary file '{dict_file}' not found.")
        return None

    engine = PasswordMutator()
    spinner = Spinner("[*] Testing millions of combinations")
    spinner.start()

    result = None
    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=num_cores) as executor:
            futures = set()
            batch = []
            batch_size = 5000

            for root_word in _generate_root_words(base_words):
                for variant in engine.variant_generator(root_word):
                    batch.append(variant)

                    if len(batch) >= batch_size:
                        futures.add(executor.submit(check_batch, batch, target_hash))
                        batch = []

                # Check completed futures without blocking
                done = {f for f in futures if f.done()}
                for fut in done:
                    futures.discard(fut)
                    res = fut.result()
                    if res:
                        result = res
                        break
                if result:
                    break

            if not result and batch:
                futures.add(executor.submit(check_batch, batch, target_hash))

            if not result:
                for fut in concurrent.futures.as_completed(futures):
                    res = fut.result()
                    if res:
                        result = res
                        break

            # Cancel any futures that haven't started yet
            for fut in futures:
                fut.cancel()

    finally:
        spinner.stop()

    if result:
        print(f"\n[SUCCESS] Password cracked: {result}")
    else:
        print("\n[FAILURE] Hash not found. Try adding better words to your dictionary.")

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF Brute-Force Demo Tool")
    parser.add_argument('--dict', default='words.txt', metavar='FILE',
                        help='Dictionary file (default: words.txt)')
    parser.add_argument('--hash', default=None, metavar='HASH',
                        help='Target SHA-256 hash (overrides hashes.txt)')
    args = parser.parse_args()

    target_hash = args.hash
    if not target_hash:
        try:
            with open('hashes.txt', 'r') as f:
                line = f.readline().strip()
                target_hash = line.split(':')[-1].strip() if ':' in line else line
        except Exception as e:
            print(f"Error reading hashes.txt: {e}")
            sys.exit(1)

    if not target_hash:
        print("Error: No target hash provided. Use --hash or populate hashes.txt.")
        sys.exit(1)

    execute_bruteforce(args.dict, target_hash)
