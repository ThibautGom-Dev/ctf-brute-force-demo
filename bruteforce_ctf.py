import itertools
import hashlib
import concurrent.futures
import multiprocessing
import sys

class PasswordMutator:
    def __init__(self, target_hash):
        self.target_hash = target_hash
        # We now include uppercase letters in the substitution dictionary!
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
        """Generates variants without overwriting existing uppercase letters."""
        word = word.strip() # No more .lower() here, we keep the uppercase letters intact
        if not word:
            return
            
        grids = [self.common_subs.get(char, [char]) for char in word]
        
        for base in itertools.product(*grids):
            v = ''.join(base)
            for term in self.terminators:
                yield v + term          
                yield term + v    

def check_batch(variants_batch, target_hash):
    """Checks a batch of passwords."""
    for password in variants_batch:
        if hashlib.sha256(password.encode()).hexdigest() == target_hash:
            return password
    return None

def load_hash_from_file(file_path):
    """Allows the user to select a level from the file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [line for line in f if line.strip()]
            print("\n--- SELECT TARGET LEVEL ---")
            for idx, line in enumerate(lines):
                print(f"[{idx + 1}] {line.strip()[:45]}... (Hash hidden)")
            
            choice = int(input("\nSelect a level (1-3): ")) - 1
            if 0 <= choice < len(lines):
                return lines[choice].split(':')[1].strip()
            else:
                print("Invalid choice.")
                sys.exit()
    except FileNotFoundError:
        print(f"Error: Could not find '{file_path}'.")
        sys.exit()
    except ValueError:
        print("Invalid input. Please enter a number.")
        sys.exit()

def execute_bruteforce(dict_file, target):
    engine = PasswordMutator(target)
    num_cores = multiprocessing.cpu_count()
    
    print(f"\n--- Initializing Brute-Force Workers: {num_cores} cores allocated ---")
    
    try:
        with open(dict_file, 'r', encoding='utf-8') as f:
            base_words = [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Dictionary file '{dict_file}' not found.")
        return

    print(f"[*] Loaded {len(base_words)} root words.")
    combined_words = []
    
    # 1. Single words (lowercase and uppercase)
    for w in base_words:
        combined_words.append(w)
        combined_words.append(w.capitalize())

    # 2. Combinations of 2 words (e.g., busterjohn, BusterJohn)
    for w1, w2 in itertools.permutations(base_words, 2):
        combined_words.append(w1 + w2)
        combined_words.append(w1.capitalize() + w2.capitalize())
        
    # 3. Combinations of 3 words (e.g., busterjohn1990, BusterJohn1990)
    for w1, w2, w3 in itertools.permutations(base_words, 3):
        combined_words.append(w1 + w2 + w3)
        combined_words.append(w1.capitalize() + w2.capitalize() + w3.capitalize())

    # Remove any duplicates
    combined_words = list(set(combined_words))
    print(f"[*] Generated {len(combined_words)} combinator roots to test.")

    # The rest of the function remains the same (ProcessPoolExecutor)
    with concurrent.futures.ProcessPoolExecutor(max_workers=num_cores) as executor:
        futures = []
        batch = []
        batch_size = 10000 

        for root_word in combined_words:
            for variant in engine.variant_generator(root_word):
                batch.append(variant)
                
                if len(batch) >= batch_size:
                    futures.append(executor.submit(check_batch, batch, target))
                    batch = []
            
            for fut in [fut for fut in futures if fut.done()]:
                res = fut.result()
                if res:
                    print(f"\n[SUCCESS] Password cracked: {res}")
                    return res
                futures.remove(fut)

        if batch:
            futures.append(executor.submit(check_batch, batch, target))
        
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                print(f"\n[SUCCESS] Password cracked: {res}")
                return res
                        
    print("\n[FAILURE] Hash not found. Try adding better words to your dictionary.")

if __name__ == "__main__":
    print("Welcome to the OSINT Password Cracking Lab")
    
    # Load the target hash
    target_hash = load_hash_from_file('hashes.txt')
    
    # Launch the combinatorial attack
    execute_bruteforce('words.txt', target_hash)
