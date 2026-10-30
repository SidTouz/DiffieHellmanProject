from Crypto.Util.number import isPrime
TRANSCRIPT_FIELDS = {
    "protocol": str, "initiator": str, "responder": str,
    "p": int, "g": int, "A": int, "B": int,
    "nonce_A": str, "nonce_B": str,
}
PROTOCOL = "DH-CLASSROOM-AUTH-v1"

def check_integer(n):
    return type(n) is int

def check_nonce(nonce):
    if type(nonce) is not str:
        raise TypeError("Nonce must be a string.")

    if len(nonce) != 64:
        raise ValueError("Invalid nonce length.")
    
    try:
        decoded = bytes.fromhex(nonce)
    except ValueError:
        raise ValueError("Nonce must be hexadecimal.")

    if len(decoded) != 32:
        raise ValueError("Invalid nonce.")

def check_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result

def check_prime(p):
    if not check_integer(p):
        raise TypeError("p must be an integer")
    if p.bit_length() not in range(16, 33):
            raise ValueError("Invalid prime bit length")
    if p % 2 == 0:
        raise ValueError("p must be odd")
    if not isPrime(p):
            raise ValueError("p is not prime")

def check_range(value, p, name):
    if not 2 <= value <= p - 2:
        raise ValueError(f"{name} is out of range")

def check_fields(obj, schema):
    if type(obj) is not dict:
        raise ValueError("Expected a JSON object")
    if set(obj) != set(schema):
        raise ValueError("Missing or unexpected fields")
    for name, expected in schema.items():
        if type(obj[name]) is not expected:
            raise TypeError(f"Field '{name}' has the wrong type")
    for name in ("nonce_A", "nonce_B"):
        if name in obj:
            check_nonce(obj[name])
    if obj["protocol"] != PROTOCOL:
        raise ValueError("Wrong protocol label")

def check_transcript(transcript):
    check_fields(transcript, TRANSCRIPT_FIELDS)

