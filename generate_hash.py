import hashlib

password = input("Entrez le mot de passe pour générer le hash : ")
hash_result = hashlib.sha256(password.encode()).hexdigest()

print(f"\nHash SHA-256 pour '{password}':")
print(hash_result)