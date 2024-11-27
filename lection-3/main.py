from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

try:
    # Генерація RSA ключів
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Стандартний вибір для експоненти
        key_size=2048,          # Розмір ключа (2048 біт)
    )
    public_key = private_key.public_key()

    # Генерація симетричного ключа AES
    aes_key = os.urandom(32)  # AES-256 використовує 32 байти (256 біт)

    # Шифрування AES ключа за допомогою RSA відкритого ключа
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Використання MGF1 з SHA-256
            algorithm=hashes.SHA256(),                    # Хеш-функція SHA-256
            label=None
        )
    )

    # Дешифрування AES ключа за допомогою RSA приватного ключа
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Має відповідати шифруванню
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Перевірка, що дешифровані ключі збігаються
    assert aes_key == decrypted_aes_key, "Ключі не збігаються!"

    # Шифрування даних за допомогою AES
    data = "Це секретне повідомлення.".encode('utf-8')  # Перетворення рядка в байти
    iv = os.urandom(16)  # Генерація 16-байтового IV для AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()

    # Розшифрування даних за допомогою AES
    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CFB(encrypted_data[:16]))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    # Перевірка, що розшифровані дані збігаються з оригіналом
    assert data == decrypted_data, "Розшифровані дані не збігаються з оригіналом!"

    # Вивід результатів
    print("Зашифровані дані:", encrypted_data)
    print("Розшифровані дані:", decrypted_data.decode('utf-8'))

except Exception as e:
    print(f"Сталася помилка: {e}")
