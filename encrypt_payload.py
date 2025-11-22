import sys

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    res = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        res.append(b ^ S[(S[i] + S[j]) % 256])
    return res

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <input_file> <output_file> <key>")
    sys.exit(1)

input_path = sys.argv[1]
output_path = sys.argv[2]
key = sys.argv[3].encode('utf-8')

try:
    with open(input_path, 'rb') as f:
        data = f.read()
    
    encrypted_data = rc4(key, data)
    
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
        
    print(f"Successfully encrypted {input_path} to {output_path} with key '{sys.argv[3]}'")

except Exception as e:
    print(f"Error: {e}")
