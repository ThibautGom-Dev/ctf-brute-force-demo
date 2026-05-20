import itertools
import hashlib
import concurrent.futures
import multiprocessing

class PasswordMutator:
    def __init__(self):
        # Substitution dictionary
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
        self.terminators = ['', '!', '?', '@', '#']

    def variant_generator(self, word):
        word = word.strip()
        if not word: return
            
        grids = [self.common_subs.get(char, [char]) for char in word]
        
        for base in itertools.product(*grids):
            v = ''.join(base)
            for term in self.terminators:
                yield v + term          
                yield term + v    

def check_batch(variants_batch, target_hash):
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
    # Generate combinations
    for w in base_words:
        combined_words.append(w); combined_words.append(w.capitalize())
    for w1, w2 in itertools.permutations(base_words, 2):
        combined_words.append(w1 + w2); combined_words.append(w1.capitalize() + w2.capitalize())
    for w1, w2, w3 in itertools.permutations(base_words, 3):
        combined_words.append(w1 + w2 + w3); combined_words.append(w1.capitalize() + w2.capitalize() + w3.capitalize())

    combined_words = list(set(combined_words))
    
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
            
            # Clean finished futures
            for fut in [f for f in futures if f.done()]:
                res = fut.result()
                if res:
                    print(f"\n[SUCCESS] Password cracked: {res}")
                    return res
                futures.remove(fut)

if __name__ == "__main__":
    # Read hashes.txt
    try:
        with open('hashes.txt', 'r') as f:
            target_hash = f.readline().strip()
            if ":" in target_hash:
                target_hash = target_hash.split(':')[1].strip()
        
        execute_bruteforce('words.txt', target_hash)
    except Exception as e:
        print(f"Error loading hash: {e}")
