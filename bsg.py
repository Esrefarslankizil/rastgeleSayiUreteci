import struct

class SemazenCipher:
    def __init__(self, key_str):
        # Anahtarı string'den 64-bitlik bir tamsayıya çeviriyoruz (Hash mantığıyla)
        # Bu bizim başlangıç "çemberimiz".
        self.state = 0
        for char in key_str:
            self.state = (self.state << 5) ^ (self.state >> 59) ^ ord(char)
            self.state &= 0xFFFFFFFFFFFFFFFF # 64-bit sınırında tut (Maskeleme)

    def _rotate_left(self, val, bits, size=64):
        """
        Bitleri sola döndürür. Soldan taşanlar sağdan geri girer.
        (Tek mantık budur: Çember sürekli döner)
        """
        return ((val << bits) | (val >> (size - bits))) & 0xFFFFFFFFFFFFFFFF

    def encrypt(self, plaintext):
        encrypted_bytes = bytearray()
        
        # Orijinal state bozulmasın diye geçici bir kopyasını alıyoruz
        temp_state = self.state 

        for char in plaintext:
            char_code = ord(char)

            # 1. MANTIK: DÖNÜŞ (Semazen döner)
            # Anahtarı 5 bit sola döndür
            temp_state = self._rotate_left(temp_state, 5)

            # 2. İŞLEM: XOR
            # Anahtarın son 8 bitiyle karakteri şifrele
            keystream_byte = temp_state & 0xFF
            cipher_val = char_code ^ keystream_byte

            # 3. MANTIK: HAFIZA (Geri Besleme)
            # Şifreli çıkan sonucu, dönen anahtarın içine katıyoruz.
            # Bu sayede metin değiştikçe dönüşün ekseni de kayar.
            temp_state ^= cipher_val

            encrypted_bytes.append(cipher_val)

        # Sonucu hex string olarak döndür (okunabilir olsun)
        return encrypted_bytes.hex()

    def decrypt(self, hex_ciphertext):
        try:
            cipher_bytes = bytes.fromhex(hex_ciphertext)
        except ValueError:
            return "Hata: Geçersiz Hex formatı."

        decrypted_chars = []
        temp_state = self.state # Aynı başlangıç anahtarı

        for cipher_val in cipher_bytes:
            # 1. MANTIK: DÖNÜŞ (Şifrelerken ne yaptıysak aynısı)
            temp_state = self._rotate_left(temp_state, 5)

            # 2. İŞLEM: XOR (Tersine çevir)
            keystream_byte = temp_state & 0xFF
            plain_val = cipher_val ^ keystream_byte
            
            # 3. MANTIK: HAFIZA
            # Şifrelerken "cipher_val" eklemiştik, burada da elimizdeki "cipher_val"ı ekliyoruz.
            # DİKKAT: Decrypt ederken de STATE, şifreli veriyle beslenir.
            temp_state ^= cipher_val

            decrypted_chars.append(chr(plain_val))

        return "".join(decrypted_chars)

# --- SENARYO ---

if __name__ == "__main__":
    # 1. Hazırlık
    anahtar_kelime = "Mevlana"
    sistem = SemazenCipher(anahtar_kelime)

    # 2. Mesaj
    gizli_mesaj = "Ne olursan ol yine gel."

    print(f"Mesaj: {gizli_mesaj}")
    print(f"Anahtar: {anahtar_kelime}")
    print("-" * 30)

    # 3. Şifreleme
    sifreli = sistem.encrypt(gizli_mesaj)
    print(f"Şifreli (Hex): {sifreli}")

    # 4. Çözme
    cozulen = sistem.decrypt(sifreli)
    print(f"Çözülen: {cozulen}")

    # 5. Bütünlük Testi (Avalanche Effect)
    # Mesajın sadece tek bir harfini değiştirirsek şifre tamamen değişmeli.
    print("-" * 30)
    sistem2 = SemazenCipher(anahtar_kelime)
    sifreli2 = sistem2.encrypt("Ne olursan ol yine gel!") # Sonunda ünlem var
    print(f"Sadece '!' farkı: {sifreli2}")
    
    # Farkı gör: Şifreli metinlerin ne kadar benzediğine (benzemediğine) bak.