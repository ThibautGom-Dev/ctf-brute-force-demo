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
        # Used as both prefix and suffix: symbols + numbers can appear on either side.
        # Level examples:  BusterBuster        → ('', root, '')
        #                  Bust3rBust3r!        → ('', root, '!')
        #                  1Bust3rS3attel1990!  → ('1', root, '!')
        self.affixes = ['', '!', '?', '@', '#', '1', '13', '90', '1990', '123', '2024']

    def leet_variants(self, word, max_subs=2):
        """Yield leet variants sorted by substitution count (fewest first).

        max_subs caps how many characters can differ from the original, which
        keeps the per-word variant count small (a 7-char word stays under ~100
        variants vs ~400 unbounded) while still covering realistic passwords.
        """
        grids = [self.common_subs.get(c, [c]) for c in word]
        combos = list(itertools.product(*grids))
        combos.sort(key=lambda combo: sum(a != b for a, b in zip(word, combo)))
        for combo in combos:
            if sum(a != b for a, b in zip(word, combo)) > max_subs:
                break  # list is sorted so all remaining combos exceed the cap
            yield ''.join(combo)

    def build_word_cache(self, base_words):
        """Pre-compute leet variants for every word form (lower + capitalized).

        Caching avoids recomputing the same substitutions when a word appears
        in multiple multi-word combinations.
        """
        cache = {}
        for w in base_words:
            forms = list({w.lower(), w.capitalize()})
            seen_variants = set()
            ordered = []
            for form in forms:
                for v in self.leet_variants(form):
                    if v not in seen_variants:
                        seen_variants.add(v)
                        ordered.append(v)
            cache[w] = ordered
        return cache


def _word_combos(base_words, n):
    """Yield n-word combinations, prioritising permutations (no repeats) first.

    Real passwords rarely repeat the exact same word multiple times (e.g.
    busterseatterseattel).  By trying permutations first we reach the target
    faster without ever skipping valid candidates.
    """
    seen = set()
    # Distinct-word permutations first (fast path for realistic passwords)
    if n <= len(base_words):
        for combo in itertools.permutations(base_words, n):
            seen.add(combo)
            yield combo
    # Then combinations with repeated words (complete coverage)
    for combo in itertools.product(base_words, repeat=n):
        if combo not in seen:
            yield combo


def _generate_candidates(base_words, mutator):
    """Yield every candidate password for 1-, 2-, and 3-word combinations.

    Uses per-word leet variant caching so each word's substitutions are
    computed only once, regardless of how many combinations it appears in.
    Wraps each combined root with all (prefix, numeric suffix, suffix) triples.
    """
    cache = mutator.build_word_cache(base_words)
    seen_roots = set()

    for n in range(1, 4):
        for word_combo in _word_combos(base_words, n):
            for leet_combo in itertools.product(*[cache[w] for w in word_combo]):
                root = ''.join(leet_combo)
                if root in seen_roots:
                    continue
                seen_roots.add(root)
                for prefix in mutator.affixes:
                    for suffix in mutator.affixes:
                        yield prefix + root + suffix


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

            for candidate in _generate_candidates(base_words, engine):
                batch.append(candidate)

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
