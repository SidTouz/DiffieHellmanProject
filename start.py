import secrets
import json
import time
import hashlib
import unittest
import sys

PROTOCOL = 'DH-CLASSROOM-AUTH-v1'

class DiffieHellman:
    
    def __init__(self, bits):
        self.p, _ = self.generatePrime(bits)
        self.factors = self.prime_factors(self.p-1)
        self.generator = self.find_generator()
        self.A_privatekey, self.B_privatekey = self.set_privatekey()
        self.A_publickey, self.B_publickey = self.set_publickey()
        self.A_nonce, self.B_nonce = self.set_nonce()
        self.data = None
        
    def modular_exponentiation(self, base, exponent, modulus):
        if not base.is_integer():
            raise("Base is not an integer value.")
        if exponent < 0:
            raise("Negative exponent.")
        if modulus <= 0:
            raise("Modulus must be positive.")

        result = 1 % modulus
        base = base % modulus

        while exponent >0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            base = (base * base) % modulus
            exponent = exponent // 2

        return result

    def generatePrime(self, bits):
        starttime = time.time()
        from Crypto.Util.number import getPrime, isPrime
        if not bits.is_integer():
            raise("Bits is not an integer value.")
        if not 16 <= bits <= 32:
            raise("Bits value out of range.")
        
        p = getPrime(bits, randfunc=secrets.token_bytes)

        if p.bit_length != bits or not p % 2 == 0:
            raise("prime number error.")

        if not isPrime(p):
            raise("prime number error.")

        endtime = time.time()
        self.p = p
        return p, endtime - starttime

    def prime_factors(self, n):
        import math
        factors = set()
        if n <= 0:
            raise("n must be positive.")
        if n == 1:
            return factors

        while n % 2 == 0:
            n = n / 2
            factors.add(2)

        for i in range(1, math.floor(n/2), 2):
            while n % i == 0:
                    n = n / i
                    factors.add(i)
    
        return factors

    def find_generator(self):
        m = (self.p - 1) 
        check = False
        generator = None
        for g in range(2, self.p-2):
            for r in self.factors:
                result = self.modular_exponentiation(g, m // r, self.p)
                if result == 1:
                    continue
                else:
                    check = True
            if check:
                generator = g
        return generator

    def set_privatekey(self):
        a = secrets.randbelow(self.p -3) + 2
        b = secrets.randbelow(self.p -3) + 2
        self.set_publickey()
        return a, b

    def set_publickey(self):
        A = self.modular_exponentiation(self.generator, self.A_privatekey, self.p)
        B = self.modular_exponentiation(self.generator, self.B_privatekey, self.p)
        
        if not 2<= A <= self.p-2 or not 2<= B <= self.p-2:
            _, _ = self.set_privatekey()

        return A,B

    def verify(self, message_bytes):
        from cryptography.hazmat.primitives.asymmetric import ed25519   
        from cryptography.exceptions import InvalidSignature     
        signing_key = ed25519.Ed25519PrivateKey.generate()
        verification_key = signing_key.public_key()
        try:
            signature = signing_key.sign(message_bytes)
            verification_key.verify(signature, message_bytes)
        except InvalidSignature:
            print("aborting exchange")
            sys.exit()

    def set_nonce(self):
        nonce_1 = secrets.token_bytes(32)
        nonce_2 = secrets.token_bytes(32)
        return nonce_1, nonce_2

    def send_message(self, msg):
        msg = {
            "A":self.A_publickey,
            "g":self.generator,
            "p": self.p, 
            "nonce A": self.A_nonce
        }
        self.data = json.dumps(msg, sort_keys=True, separators=",").encode("utf-8")

    def recieve_message(self):
        from Crypto.Util.number import isPrime
        self.verify(self.data)

        if not isPrime(self.data["p"]):
            raise("Failed to verify p")
        verify_factors = self.prime_factors(self.p -1)
        if self.factors != verify_factors:
            raise("Failed to verify factors")
        if self.generator != self.data["g"]:
            raise("Failed to verify generator")
        if self.A_nonce != self.data["nonce A"]:
            print("Failed to verify nonce.")
        if not 1 <= self.data["A"] <= self.p - 1:
            raise("A is outside of expected range")
        if not 1 <= self.data["B"] <= self.p - 1:
                    raise("A is outside of expected range")
        
        return "ACCEPT"

    def calculate_secrets(self):
        a_secret = self.modular_exponentiation(self.B_publickey, self.A_privatekey, self.p)
        b_secret = self.modular_exponentiation(self.A_publickey, self.B_privatekey, self.p)
        if a_secret == b_secret:
            return True
        else:
            return False

        
if __name__ == '__main__':
    bits = input("Please enter the number of bits: ")
    exchange_1 = DiffieHellman(bits)

    Alice_payload = {
        "Protocol": PROTOCOL,
        "Message Type": "init",
        "Initiator": "Alice",
        "Responder": "Bob"
    }
    exchange_1.send_message(Alice_payload)
    answer = exchange_1.recieve_message()

    if answer == "ACCEPT":
        Bob_payload = {
                "Protocol": PROTOCOL,
                "Message Type": "response",
                "Initiator": "Bob",
                "Responder": "Alice",
                "Transcript": "hello"
            }
        exchange_1.send_message(Bob_payload)

    answer_2 = exchange_1.recieve_message()
    if answer == "ACCEPT":
        Alice_payload = {
                "Protocol": PROTOCOL,
                "Message Type": "finish",
                "Transcript": "hello"
            }
        exchange_1.send_message(Alice_payload)
    final_answer = exchange_1.recieve_message()

    if final_answer == "ACCEPT":
        check = exchange_1.calculate_secrets()
        print("Transcript Authenticated: TRUE\nShared secrets match: ",check)

    eve_private_exponent1 = 3
    eve_private_exponent2 = 7
    eve_public_1 = 10
    eve_public_2 = 17