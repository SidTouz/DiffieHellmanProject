import unittest
from Crypto.Util.number import isPrime

from main import (
    ALICE, BOB, PROTOCOL, Party,
    check_prime, decode_message, encode_message, generate_prime,
    is_generator, modular_exponentiation, new_nonce, prime_factors,
    trusted_setup
)

BAD_TYPES = (1.5, 3.0, "3", None, True, False, [3])

class TestModularExponentiation(unittest.TestCase):
    def test_exponent_zero(self):
        self.assertEqual(modular_exponentiation(5, 0, 7), 1)
        self.assertEqual(modular_exponentiation(0, 0, 7), 1)   

    def test_modulus_one(self):
        for base in (-3, 0, 5, 10**6):
            for exp in (0, 1, 7):
                with self.subTest(base=base, exp=exp):
                    self.assertEqual(modular_exponentiation(base, exp, 1), 0)

    def test_negative_base(self):
        for base in (-1, -2, -7, -100):
            for exp in (0, 1, 2, 5, 10):
                with self.subTest(base=base, exp=exp):
                    result = modular_exponentiation(base, exp, 13)
                    self.assertEqual(result, pow(base, exp, 13))
                    self.assertTrue(0 <= result < 13)

    def test_matches_builtin_pow(self):
        for base, exp, mod in [(2, 10, 1000), (3, 200, 65537), (12345, 6789, 99991)]:
            self.assertEqual(modular_exponentiation(base, exp, mod), pow(base, exp, mod))

    def test_invalid_values(self):
        with self.assertRaises(ValueError):
            modular_exponentiation(2, -1, 7)       
        for bad_mod in (0, -5):
            with self.assertRaises(ValueError):
                modular_exponentiation(2, 3, bad_mod)

    def test_wrong_types(self):
        for bad in BAD_TYPES:
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    modular_exponentiation(bad, 3, 7)
                with self.assertRaises(TypeError):
                    modular_exponentiation(2, bad, 7)
                with self.assertRaises(TypeError):
                    modular_exponentiation(2, 3, bad)


class TestGeneratePrime(unittest.TestCase):
    def test_default_is_16_bits(self):
        p, _ = generate_prime()
        self.assertEqual(p.bit_length(), 16)

    def test_size_oddness_and_primality(self):
        for bits in (16, 17, 24, 32):
            with self.subTest(bits=bits):
                p, elapsed = generate_prime(bits)
                self.assertEqual(p.bit_length(), bits)
                self.assertEqual(p % 2, 1)
                self.assertTrue(isPrime(p))
                self.assertIsInstance(elapsed, float)
                self.assertGreaterEqual(elapsed, 0.0)

    def test_out_of_range_size(self):
        for bits in (15, 33, 0, -16, 10**6):
            with self.subTest(bits=bits):
                with self.assertRaises(ValueError):
                    generate_prime(bits)

    def test_invalid_requested_size_types(self):
        for bits in (True, False, 16.0, "16", None):
            with self.subTest(bits=bits):
                with self.assertRaises(TypeError):
                    generate_prime(bits)


class TestCheckPrime(unittest.TestCase):
    def test_accepts_valid_primes(self):
        check_prime(65537)
        check_prime(2**31 - 1)

    def test_rejects_composite_32769(self):
        # 32769 = 3^2 * 11 * 331: odd, 16 bits, fails prime check
        with self.assertRaisesRegex(ValueError, "not prime"):
            check_prime(32769)

    def test_rejects_even(self):
        with self.assertRaisesRegex(ValueError, "odd"):
            check_prime(65536)

    def test_rejects_bad_bit_length(self):
        for p in (2, 23, 2**33, 2**4000 + 1):    
            with self.subTest(p=p):
                with self.assertRaisesRegex(ValueError, "bit length"):
                    check_prime(p)

    def test_rejects_wrong_types(self):
        for bad in (23.0, "23", None, True):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    check_prime(bad)


class TestPrimeFactors(unittest.TestCase):
    def test_one_gives_empty_set(self):
        self.assertEqual(prime_factors(1), set())

    def test_22(self):
        self.assertEqual(prime_factors(22), {2, 11})

    def test_repeated_factors_65536(self):
        self.assertEqual(prime_factors(65536), {2})

    def test_distinct_and_prime_inputs(self):
        self.assertEqual(prime_factors(360), {2, 3, 5})
        self.assertEqual(prime_factors(65537), {65537})

    def test_invalid_values(self):
        for n in (0, -4):
            with self.assertRaises(ValueError):
                prime_factors(n)

    def test_wrong_types(self):
        for bad in ("6", 6.0, True, None):
            with self.assertRaises(TypeError):
                prime_factors(bad)


class TestGeneratorCheck(unittest.TestCase):
    def test_p23_accepts_5_rejects_2(self):
        factors = prime_factors(22)
        self.assertTrue(is_generator(5, 23, factors))
        self.assertFalse(is_generator(2, 23, factors))   

    def test_p65537_accepts_3(self):
        self.assertTrue(is_generator(3, 65537, prime_factors(65536)))

    def test_p65537_rejects_2(self):
        self.assertFalse(is_generator(2, 65537, prime_factors(65536)))  

def forged_init(signer, p, g, A, responder=BOB):
    payload = {
        "protocol": PROTOCOL, "message_type": "init",
        "initiator": signer.name, "responder": responder,
        "p": p, "g": g, "A": A, "nonce_A": new_nonce(),
    }
    data = encode_message(payload)
    return data, signer.sign(data)

class TestProtocol(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = Party(ALICE), Party(BOB)
        trusted_setup(self.alice, self.bob)

    def run_exchange(self, alice=None, bob=None, bits=16):
        alice, bob = alice or self.alice, bob or self.bob
        m1 = alice.start_exchange(bob.name, bits)
        m2 = bob.handle_init(m1, alice.name)
        m3 = alice.handle_response(m2, bob.name)
        bob.handle_finish(m3, alice.name)
        return m1, m2, m3



    def test_valid_exchange(self):
        for bits in (16, 24):
            with self.subTest(bits=bits):
                self.run_exchange(bits=bits)
                self.assertIsNotNone(self.alice.shared_secret)
                self.assertEqual(self.alice.shared_secret, self.bob.shared_secret)
                self.assertIsNone(self.alice.pending)
                self.assertIsNone(self.bob.pending)

    def test_messages_are__well_formed(self):
        m1, m2, m3 = self.run_exchange()
        for data, _sig in (m1, m2, m3):
            self.assertLessEqual(len(data), 4096)
            self.assertEqual(encode_message(decode_message(data)), data)
        self.assertEqual(decode_message(m1[0])["protocol"], PROTOCOL)

    def test_p65537_g3_accepted_by_bob(self):
        self.bob.handle_init(forged_init(self.alice, 65537, 3, 5), ALICE)

    def test_p65537_g2_rejected_by_bob(self):
        with self.assertRaisesRegex(Exception, "generator"):
            self.bob.handle_init(forged_init(self.alice, 65537, 2, 5), ALICE)

    def test_composite_p_32769_rejected_by_bob(self):
        with self.assertRaisesRegex(Exception, "not prime"):
            self.bob.handle_init(forged_init(self.alice, 32769, 3, 5), ALICE)

    def test_out_of_range_A_rejected_by_bob(self):
        for A in (0, 1, 65536, 65537):
            with self.subTest(A=A):
                with self.assertRaises(Exception):
                    self.bob.handle_init(forged_init(self.alice, 65537, 3, A), ALICE)



    def test_wrong_trusted_key_for_alice(self):
        self.bob.trusted[ALICE] = Party("Other").public_key
        m1 = self.alice.start_exchange(BOB)
        with self.assertRaisesRegex(Exception, "Signature"):
            self.bob.handle_init(m1, ALICE)
        self.assertIsNone(self.bob.shared_secret)

    def test_wrong_trusted_key_for_bob(self):
        self.alice.trusted[BOB] = Party("Other").public_key
        m1 = self.alice.start_exchange(BOB)
        m2 = self.bob.handle_init(m1, ALICE)
        with self.assertRaisesRegex(Exception, "Signature"):
            self.alice.handle_response(m2, BOB)
        self.assertIsNone(self.alice.shared_secret)

    def test_missing_trusted_key(self):
        self.bob.trusted = {}
        m1 = self.alice.start_exchange(BOB)
        with self.assertRaisesRegex(Exception, "No trusted key"):
            self.bob.handle_init(m1, ALICE)

    def test_eve_claiming_to_be_alice(self):
        eve = Party(ALICE)          
        m1 = eve.start_exchange(BOB)
        with self.assertRaisesRegex(Exception, "Signature"):
            self.bob.handle_init(m1, ALICE)

    def test_nonces_fresh_across_exchanges(self):
        seen_A, seen_B = set(), set()
        for _ in range(5):
            m1, m2, _m3 = self.run_exchange()
            nonce_A = decode_message(m1[0])["nonce_A"]
            nonce_B = decode_message(m2[0])["transcript"]["nonce_B"]
            self.assertNotEqual(nonce_A, nonce_B)
            seen_A.add(nonce_A)
            seen_B.add(nonce_B)
        self.assertEqual(len(seen_A), 5)
        self.assertEqual(len(seen_B), 5)

    

    def test_stale_response_rejected_during_new_session(self):
        _m1, old_m2, _m3 = self.run_exchange()
        self.alice.start_exchange(BOB)                    # new session 
        with self.assertRaisesRegex(Exception, "pending session"):
            self.alice.handle_response(old_m2, BOB)
        self.assertIsNone(self.alice.shared_secret)

    def test_stale_response_rejected_after_completion(self):
        _m1, old_m2, _m3 = self.run_exchange()
        with self.assertRaisesRegex(Exception, "out of order"):
            self.alice.handle_response(old_m2, BOB)

   

    def test_duplicate_finish_rejected(self):
        _m1, _m2, m3 = self.run_exchange()
        secret = self.bob.shared_secret
        with self.assertRaises(Exception):
            self.bob.handle_finish(m3, ALICE)
        self.assertEqual(self.bob.shared_secret, secret)

    def test_duplicate_response_rejected(self):
        _m1, m2, _m3 = self.run_exchange()
        secret = self.alice.shared_secret
        with self.assertRaises(Exception):
            self.alice.handle_response(m2, BOB)
        self.assertEqual(self.alice.shared_secret, secret)

   #wrong message order

    def _fresh_pair_with_same_keys(self):
        alice2, bob2 = Party(ALICE), Party(BOB)
        alice2.trusted = {BOB: self.bob.public_key}
        bob2.trusted = {ALICE: self.alice.public_key}
        return alice2, bob2

    def test_finish_before_init(self):
        _m1, _m2, m3 = self.run_exchange()
        _alice2, bob2 = self._fresh_pair_with_same_keys()
        with self.assertRaises(Exception):
            bob2.handle_finish(m3, ALICE)

    def test_response_before_start(self):
        _m1, m2, _m3 = self.run_exchange()
        alice2, _bob2 = self._fresh_pair_with_same_keys()
        with self.assertRaises(Exception):
            alice2.handle_response(m2, BOB)

    def test_wrong_message_type_for_handler(self):
        m1 = self.alice.start_exchange(BOB)
        with self.assertRaises(Exception):
            self.bob.handle_finish(m1, ALICE)
        with self.assertRaises(Exception):
            self.alice.handle_response(m1, BOB)

    def test_response_while_awaiting_finish(self):
        m1 = self.alice.start_exchange(BOB)
        m2 = self.bob.handle_init(m1, ALICE)
        with self.assertRaisesRegex(Exception, "out of order"):
            self.bob.handle_response(m2, ALICE)

    def test_finish_while_awaiting_response(self):
        _m1, _m2, old_m3 = self.run_exchange()
        self.alice.start_exchange(BOB)
        with self.assertRaisesRegex(Exception, "out of order"):
            self.alice.handle_finish(old_m3, BOB)


if __name__ == "__main__":
    unittest.main()