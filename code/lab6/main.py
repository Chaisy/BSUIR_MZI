import digital_signature
p = 17
q = 19

public_key, private_key = digital_signature.generate_key_pair(p, q)

print('Open Key (Public Key): ', public_key)
print('Private Key: ', private_key)

with open('text.txt', 'r') as file:
    source_text = file.read()

hash_value = digital_signature.hash_function(source_text)
print('Hash of the source text (before signing):', hash_value)
encrypted_hash = digital_signature.encrypt(private_key, hash_value)
print('Digital Signature (Encrypted hash):', encrypted_hash)
decrypted_hash = digital_signature.decrypt(public_key, encrypted_hash)
print('Decrypted hash:', decrypted_hash)
if digital_signature.verify(public_key, encrypted_hash, hash_value):
    print('Signature verification result: Accept (signature is valid)')
else:
    print('Signature verification result: Not accept (signature is invalid)')
