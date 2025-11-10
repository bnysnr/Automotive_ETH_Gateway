signal_hex = 0x737D7F6F7D2F7F82
start_bit = 0
length = 16
start = start_bit // 8  # Startbit in Nibbles
end = length // 8  # Länge in Nibbles

# Big Endian
# Konvertierung zu Bytes und dann zu Hex-String
big_endian_bytes = signal_hex.to_bytes(length=8, byteorder="big")
result_big_endian = big_endian_bytes[start:end]  # Extrahiere die Bytes

# In Zweier-Paare speichern
big_endian_pairs = [result_big_endian[i:i+1].hex().upper() for i in range(0, len(result_big_endian), 1)]

# Ausgabe der Paare
print(f"Big Endian Pärchen: {big_endian_pairs}")

# Little Endian
# Umkehren der relevanten Bytes für Little Endian und in Paare speichern
little_endian_bytes = result_big_endian[::-1]
little_endian_pairs = [little_endian_bytes[i:i+1].hex().upper() for i in range(0, len(little_endian_bytes), 1)]

# Ausgabe
print(f"Little Endian Pärchen: {little_endian_pairs}")
