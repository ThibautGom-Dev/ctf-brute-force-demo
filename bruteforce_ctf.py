import itertools
import hashlib
import concurrent.futures
import multiprocessing
import sys
import time
import threading

class Spinner:
    """A simple command-line spinner with an elapsed timer to show progress."""
    def __init__(self, message="[*] Brute-forcing in progress"):
        self.spinner_cycle = itertools.cycle(['|', '/', '-', '\\'])
        self.stop_running = threading.Event()
        self.thread = threading.Thread(target=self.spin)
        self.message = message
        self.start_time = None

    def spin(self):
        while not self.stop_running.is_set():
            # Calculate elapsed time in seconds
            elapsed = int(time.time() - self.start_time)
            # Display message, spinner, and timer
            sys.stdout.write(f'\r{self.message} {next(self.spinner_cycle)} [{elapsed}s]')
            sys.stdout.flush()
            time.sleep(0.1)
            
        # Clear the line when stopped
        sys.stdout.write('\r' + ' ' * (len(self.message) + 20) + '\r')
        sys.stdout.flush()

    def start(self):
        self.start_time = time.time() # Record start time
        self.thread.start()

    def stop(self):
        self.stop_running.set()
        self.thread.join()

class PasswordMutator:
    def __init__(self):
        # Substitution dictionary (Leetspeak rules)
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
        # Common symbols added at the beginning or end of passwords
        self.terminators = ['', '!', '?', '@', '#']

    def variant_generator(self, word):
        """Generates variants without overwriting existing uppercase letters."""
        word = word.strip()
        if not word: return
            
        grids = [self.common_subs.get(char, [char]) for char in word]
        
        for base in itertools.product(*grids):
            v = ''.join(base)
            for term1 in self.terminators:
                for term2 in self.terminators:
                    yield term1 + v + term2

def check_batch(variants_batch, target_hash):
    """Checks a batch of generated passwords against the target hash."""
    for password in variants_batch:
        if hashlib.sha256(password.encode()).hexdigest() == target_hash:
            return password
    return None

def execute_bruteforce(dict_file, target_hash):
    engine = PasswordMutator()
    num_cores = multiprocessing.cpu_count()
    
    print(f"\n--- Initializing Brute-Force Workers: {num_cores} cores ---")
    
    try:
        with open(dict_file, 'r', encoding='utf-8') as f:
            base_words = [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Dictionary file '{dict_file}' not found.")
        return

    combined_words = []
    
    # 1. Single words 
    for w in base_words:
        combined_words.append(w); combined_words.append(w.capitalize())
        
    # 2. Combinations of 2 words
    for w1, w2 in itertools.product(base_words, repeat=2):
        combined_words.append(w1 + w2)
        combined_words.append(w1.capitalize() + w2.capitalize())
        
    # 3. Combinations of 3 words
    for w1, w2, w3 in itertools.product(base_words, repeat=3):
        combined_words.append(w1 + w2 + w3)
        combined_words.append(w1.capitalize() + w2.capitalize() + w3.capitalize())

    combined_words = list(set(combined_words))
    
    # Start the loading animation with the timer
    spinner = Spinner("[*] Testing millions of combinations")
    spinner.start()
    
    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=num_cores) as executor:
            futures = []
            batch = []
            batch_size = 5000 

            for root_word in combined_words:
                for variant in engine.variant_generator(root_word):
                    batch.append(variant)
                    
                    if len(batch) >= batch_size:
                        futures.append(executor.submit(check_batch, batch, target_hash))
                        batch = []
                
                for fut in [f for f in futures if f.done()]:
                    res = fut.result()
                    if res:
                        spinner.stop() 
                        print(f"\n[SUCCESS] Password cracked: {res}")
                        return res
                    futures.remove(fut)

            if batch:
                futures.append(executor.submit(check_batch, batch, target_hash))
                
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    spinner.stop() 
                    print(f"\n[SUCCESS] Password cracked: {res}")
                    return res
                    
    finally:
        # Stop the spinner no matter what happens
        spinner.stop()

    print("\n[FAILURE] Hash not found. Try adding better words to your dictionary.")

if __name__ == "__main__":
    try:
        with open('hashes.txt', 'r') as f:
            target_hash = f.readline().strip()
            if ":" in target_hash:
                target_hash = target_hash.split(':')[1].strip()
        
        execute_bruteforce('words.txt', target_hash)
    except Exception as e:
        print(f"Error: {e}")
