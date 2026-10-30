import json
import secrets
import unittest
import auto_tests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from utils import *
from testing import *

PROTOCOL = "DH-CLASSROOM-AUTH-v1"
MAX_MESSAGE_SIZE = 4096
ALICE, BOB = "Alice", "Bob"

TRANSCRIPT_FIELDS = {
    "protocol": str, "initiator": str, "responder": str,
    "p": int, "g": int, "A": int, "B": int,
    "nonce_A": str, "nonce_B": str,
}
INIT_FIELDS = {
    "protocol": str, "message_type": str, "initiator": str, "responder": str,
    "p": int, "g": int, "A": int, "nonce_A": str,
}
RESPONSE_FIELDS = {"protocol": str, "message_type": str, "transcript": dict}
FINISH_FIELDS = {"protocol": str, "message_type": str, "transcript": dict}

def new_nonce():
    return secrets.token_bytes(32).hex()

def encode_message(msg):
    data = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError("Message exceeds maximum size")
    return data

def decode_message(data):
    if type(data) is not bytes:
        raise TypeError("Message must be bytes")
    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError("Message exceeds maximum size")
    message = json.loads(data.decode("utf-8"), object_pairs_hook=check_duplicates)
    if type(message) is not dict:
        raise ValueError("Message must be a JSON object")
    return message

def parse_message(message, schema, message_type):
    if type(message) is not tuple or len(message) != 2:
        raise ValueError("Malformed message")
    payload_bytes, signature = message
    if type(signature) is not bytes:
        raise TypeError("Signature must be bytes")

    payload = decode_message(payload_bytes)
    check_fields(payload, schema)
    if payload["message_type"] != message_type:
        raise ValueError("Unexpected message type")
    if encode_message(payload) != payload_bytes:
        raise ValueError("Payload is not canonically encoded")
    return payload, payload_bytes, signature

class Party:

    def __init__(self, name):
        self.name = name
        self.signing_key = Ed25519PrivateKey.generate()   
        self.public_key = self.signing_key.public_key()
        self.trusted = {}            
        self.pending = None
        self.shared_secret = None
        self.prime_time = None
        self.generator_time = None

    def sign(self, payload_bytes):
        return self.signing_key.sign(payload_bytes)

    def verify(self, sender, payload_bytes, signature):
        key = self.trusted.get(sender)
        if key is None:
            raise Exception(f"No trusted key for {sender}")
        try:
            key.verify(signature, payload_bytes)   
        except InvalidSignature:
            raise Exception(f"Signature verification failed for {sender}") from None

    def require_pending(self, peer, state):
        p = self.pending
        if p is None or p["peer"] != peer or p["state"] != state:
            raise ValueError("Message out of order")
        return p
    
    def start_exchange(self, responder, bits=16):
        self.shared_secret = None
        p, self.prime_time = generate_prime(bits)
        start = time.perf_counter()
        g = find_generator(p, prime_factors(p - 1))
        self.generator_time = time.perf_counter() - start
        a, A = generate_dh_keypair(p, g)
        nonce_A = new_nonce()

        payload = {
            "protocol": PROTOCOL, "message_type": "init",
            "initiator": self.name, "responder": responder,
            "p": p, "g": g, "A": A, "nonce_A": nonce_A,
        }
        payload_bytes = encode_message(payload)
        self.pending = {"state": "awaiting_response", "peer": responder,
                        "p": p, "g": g, "a": a, "A": A, "nonce_A": nonce_A}
        return payload_bytes, self.sign(payload_bytes)

    def handle_init(self, message, sender):
        self.shared_secret = None
        payload, payload_bytes, signature = parse_message(message, INIT_FIELDS, "init")
        if payload["initiator"] != sender or payload["responder"] != self.name:
            raise ValueError("Unexpected identities")
        self.verify(sender, payload_bytes, signature)
        print(sender, " initiation signature VALID")
        p, g, A = payload["p"], payload["g"], payload["A"]
        check_prime(p)                                   
        factors = prime_factors(p - 1)
        if not 2 <= g <= p - 2 or not is_generator(g, p, factors):
            raise ValueError("g is not a valid generator")
        check_range(A, p, "A")

        b, B = generate_dh_keypair(p, g)
        transcript = {
            "protocol": PROTOCOL, "initiator": sender, "responder": self.name,
            "p": p, "g": g, "A": A, "B": B,
            "nonce_A": payload["nonce_A"], "nonce_B": new_nonce(),
        }
        response = {"protocol": PROTOCOL, "message_type": "response",
                    "transcript": transcript}
        response_bytes = encode_message(response)
        self.pending = {"state": "awaiting_finish", "peer": sender, "transcript": transcript, "b": b}
        return response_bytes, self.sign(response_bytes)

    def handle_response(self, message, sender):
        pending = self.require_pending(sender, "awaiting_response")
        payload, payload_bytes, signature = parse_message(
            message, RESPONSE_FIELDS, "response")
        t = payload["transcript"]
        check_transcript(t)

        if t["initiator"] != self.name or t["responder"] != sender:
            raise ValueError("Unexpected identities")
        for field in ("p", "g", "A", "nonce_A"):
            if t[field] != pending[field]:
                raise ValueError(f"{field} does not match pending session")
        check_range(t["B"], t["p"], "B")
        self.verify(sender, payload_bytes, signature)
        print(sender, "response signature VALID")

        finish = {"protocol": PROTOCOL, "message_type": "finish", "transcript": t}
        finish_bytes = encode_message(finish)
        self.shared_secret = modular_exponentiation(t["B"], pending["a"], t["p"])
        self.pending = None
        return finish_bytes, self.sign(finish_bytes)

    def handle_finish(self, message, sender):
        pending = self.require_pending(sender, "awaiting_finish")
        payload, payload_bytes, signature = parse_message(
            message, FINISH_FIELDS, "finish")
        t = payload["transcript"]
        check_transcript(t)

        if t != pending["transcript"]:
            raise ValueError("Transcript does not match pending session")
        self.verify(sender, payload_bytes, signature)
        print(sender, "finish signature VALID")

        self.shared_secret = modular_exponentiation(t["A"], pending["b"], t["p"])
        self.pending = None

def trusted_setup(alice, bob):
    alice.trusted = {BOB: bob.public_key}
    bob.trusted = {ALICE: alice.public_key}

def report(authenticated, secrets_match):
    yn = lambda x: "yes" if x else "no"
    print(f"transcript authenticated: {yn(authenticated)}")
    print(f"shared secrets match: {yn(secrets_match)}")


def run_exchange(initiator, responder, bits=16):
    print("Requested prime size: ",bits, " bits.")
    try:
        m1 = initiator.start_exchange(responder.name, bits)
        m2 = responder.handle_init(m1, initiator.name)
        m3 = initiator.handle_response(m2, responder.name)
        responder.handle_finish(m3, initiator.name)
    except Exception as e:
        print(f"Exchange aborted: {e}")
        report(False, False)
        return
    print(f"prime generation took {initiator.prime_time:.6f}s")
    print(f"generator search took {initiator.generator_time:.6f}s")
    report(True, initiator.shared_secret == responder.shared_secret)


def run_message_scenarios():
    alice, bob = Party(ALICE), Party(BOB)
    trusted_setup(alice, bob)

    print("--- Alice and Bob exchange ---")
    run_exchange(alice, bob)

    print("--- Eve impersonation attack ---")
    eve = Party(ALICE)               
    eve.trusted = {BOB: bob.public_key}
    run_exchange(eve, bob)

def run_trials():
    alice, bob = Party(ALICE), Party(BOB)
    trusted_setup(alice, bob)

    print("--- 16 Bit ---")
    run_exchange(alice, bob)

    print("--- 24 Bit ---")
    run_exchange(alice, bob, bits=24)

    print("--- 32 Bit ---")
    run_exchange(alice, bob, bits=32)

if __name__ == "__main__":
    choice = input("Select a choice: \n1. Run message scenarios\n2. Run automated tests\n3. Run 16, 24, and 32 bit trials.\n\n").strip()
    if choice not in ("1","2","3"):
        raise ValueError("Invalid input")
    if choice == "1":
        run_message_scenarios()
    elif choice == "2":
        print("Running Automated Tests")
        auto_test_file = unittest.TestLoader().loadTestsFromModule(auto_tests)
        runner = unittest.TextTestRunner(verbosity=2)
        runner.run(auto_test_file)
    else:
        print("Running 16, 24, and 32 bit trials")
        run_trials()