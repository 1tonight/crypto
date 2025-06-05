from lib import (
    gen_random_salt,
    generate_eg,
    compute_dh,
    verify_with_ecdsa,
    hmac_to_aes_key,
    hmac_to_hmac_key,
    hkdf,
    encrypt_with_gcm,
    decrypt_with_gcm,
    gov_encryption_data,
    generate_ecdsa,
    sign_with_ecdsa
)

class Messenger:
    def __init__(self, private_key, public_key, gov_public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.gov_public_key = gov_public_key
        self.shared_secret = None
        self.message_keys = {}
    
    def generate_certificate(self):
        signature = sign_with_ecdsa(self.private_key, self.public_key)
        return (self.public_key, signature)
    
    def receive_certificate(self, certificate, sender_public_key):
        public_key, signature = certificate
        return verify_with_ecdsa(sender_public_key, public_key, signature)
    
    def send_message(self, receiver_public_key, message):
        if self.shared_secret is None:
            self.shared_secret = compute_dh(self.private_key, receiver_public_key)
        
        aes_key = hmac_to_aes_key(self.shared_secret)
        encrypted_message, iv, tag = encrypt_with_gcm(aes_key, message)
        
        encrypted_key = gov_encryption_data(self.gov_public_key, self.shared_secret)
        return encrypted_message, iv, tag, encrypted_key
    
    def receive_message(self, sender_public_key, encrypted_data):
        encrypted_message, iv, tag, encrypted_key = encrypted_data
        
        if self.shared_secret is None:
            self.shared_secret = compute_dh(self.private_key, sender_public_key)
        
        aes_key = hmac_to_aes_key(self.shared_secret)
        message = decrypt_with_gcm(aes_key, encrypted_message, iv, tag)
        return message
