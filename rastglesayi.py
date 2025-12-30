import base64

class NomadCipher:
    
    @staticmethod
    def encrypt(text, key):
        # Python'da metni bayt dizisine çevirmek daha sağlıklıdır
        result_bytes = bytearray()
        current_key = key
        
        for char in text:
            char_code = ord(char) # Harfin sayısal değeri (ASCII/Unicode)
            
            # 1. Adım: Anahtar Karmaşası (Tuzlama)
            # Bit kaydırma ve XOR ile geçici bir karmaşa yaratıyoruz
            salt = (current_key >> 3) ^ current_key
            
            # 2. Adım: Toplama (Sezar mantığı)
            # Mod 256, değerin 0-255 arasında kalmasını sağlar (1 byte)
            step1 = (char_code + current_key) % 256
            
            # 3. Adım: XOR işlemi
            encrypted_val = step1 ^ (salt % 255)
            
            # Sonucu listeye ekle
            result_bytes.append(encrypted_val)
            
            # GÖÇ ADIMI (Mutation):
            # Anahtarı, çıkan şifreli değerle besleyip değiştiriyoruz.
            # Böylece bir sonraki harf için anahtar tamamen farklı oluyor.
            current_key = (current_key + encrypted_val) % 65535

        # Okunabilir olması için Base64'e çeviriyoruz
        return base64.b64encode(result_bytes).decode('utf-8')

    @staticmethod
    def decrypt(enc_text, key):
        # Base64'ten ham bayt verisine geri dön
        try:
            enc_bytes = base64.b64decode(enc_text)
        except:
            return "Hata: Base64 formatı bozuk."

        result = []
        current_key = key # Başlangıç anahtarı aynı olmalı
        
        for enc_val in enc_bytes:
            # 1. Adım: Aynı tuzu hesapla (Şifrelerkenki anahtarın aynısı bizde de var)
            salt = (current_key >> 3) ^ current_key
            
            # 2. Adım: Tersten işlem (Önce XOR'u geri al)
            step1 = enc_val ^ (salt % 255)
            
            # 3. Adım: Toplamayı geri al (Çıkarma)
            # Python'da negatif modül işlemi otomatik döngüye girer,
            # yani (10 - 50) % 256 işlemi doğrudan doğru pozitif sonucu verir.
            original_val = (step1 - current_key) % 256
            
            result.append(chr(original_val))
            
            # GÖÇ ADIMI:
            # Şifreyi çözerken de anahtarı güncellemeliyiz ki
            # bir sonraki harfi doğru çözebilelim.
            current_key = (current_key + enc_val) % 65535
            
        return "".join(result)

# --- TEST ALANI (Sahne) ---

if __name__ == "__main__":
    anahtar = 1299 # Söğüt, kuruluş.
    mesaj = "Harzemşahlar ve Moğollar"
    
    print(f"--- Göçebe Algoritması Testi ---")
    print(f"Orijinal Mesaj: {mesaj}")
    print(f"Anahtar: {anahtar}")
    print("-" * 30)
    
    # Şifrele
    sifreli_mesaj = NomadCipher.encrypt(mesaj, anahtar)
    print(f"Şifreli (Base64): {sifreli_mesaj}")
    
    # Çöz
    cozulen_mesaj = NomadCipher.decrypt(sifreli_mesaj, anahtar)
    print(f"Çözülen Mesaj:  {cozulen_mesaj}")
    
    # Hatalı Anahtar Testi
    yanlis_anahtar = 1300 # Sadece 1 sayı fark var!
    hatali_cozum = NomadCipher.decrypt(sifreli_mesaj, yanlis_anahtar)
    print(f"Yanlış Anahtarla ({yanlis_anahtar}): {hatali_cozum}")
