import time
import secrets
from Crypto.Util.number import getPrime
from testing import *
MIN_BITS, MAX_BITS = 16, 32

def modular_exponentiation(base, exponent, modulus):
    if not (check_integer(base) and check_integer(exponent) and check_integer(modulus)):
        raise TypeError("base, exponent and modulus must be integers")
    if exponent < 0:
        raise ValueError("Exponent must be nonnegative")
    if modulus <= 0:
        raise ValueError("Modulus must be positive")

    result = 1 % modulus
    base = base % modulus
    while exponent >0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent = exponent // 2
    return result

def generate_prime(bits=16):
    start = time.perf_counter()

    if not check_integer(bits):
        raise TypeError("Bits is non integer value")
    if not MIN_BITS <= bits <= MAX_BITS:
        raise ValueError("bits out of range")

    p = getPrime(bits, randfunc=secrets.token_bytes)
    if not p.bit_length() == bits:
                raise ValueError("p not correct bit length")
    check_prime(p)
    endtime = time.perf_counter()
    return p, (endtime - start)

def prime_factors(n):
    if not check_integer(n):
        raise TypeError("n must be an integer value")
    if n <= 0:
        raise ValueError("n must be positive")

    factors = set()
    if n == 1:
        return factors
    
    while n % 2 == 0:
        factors.add(2)
        n = n // 2

    f = 3
    factor = 3
    while factor*factor <= n:
        while n % factor == 0:
            factors.add(factor)
            n = n // factor
        factor += 2 
    if n > 1:
        factors.add(n)
    return factors

def is_generator(g, p, factors):
    return all(modular_exponentiation(g, (p - 1) // r, p) != 1 for r in factors)

def find_generator(p, factors):
    for g in range(2, p - 1):          
        if is_generator(g, p, factors):
            return g
    raise ValueError("No generator found")

def generate_dh_keypair(p, g):
    private = secrets.randbelow(p - 3) + 2
    public = modular_exponentiation(g, private, p)
    if 2 <= public <= p - 2:
        return private, public


