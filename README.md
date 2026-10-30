# Dependencies

- pycryptodome-4.2.0
- cryptography-50.0.2

# How to run
First, in the command line, type
``python main.py``

You will be prompted to select from 3 choices:
1. Run message scenarios
2. Run automated tests
3. Run 16, 24, and 32 bit trials.

# 1. Run message scenarios

This option will execute a pre-programmed set of scenarios: a successful exchange between Bob and Alice and then an attack by Eve.

# 2. Run automated tests

This option will run automatic unit tests 

# 3. Run 16, 24, and 32 bit trials 

This option will display successful exchanges between Alice and Bob for 16, 24, and 32 bit primes. 

# Report
Finite-field Diffie-Hellman is similar to elliptic-curve Diffie-Hellman (ECDH) in some ways, but there are a few important differences to discuss. First of all is the underlying core operations: modular exponentiation versus elliptic curve scalar multiplication. 
Finite field modular exponentiation refers to the process of raising some $g$ to the power $p$ modulo $n$, ie,
    $$
        g^p\pmod{n}
    $$
    Elliptic curve scalar multiplication, on the other hand, refers to the process of adding a point $G=(x,y)$ on the elliptic curve to itself $p$ times using point addition, ie,
    $$
    p\cdot G = G + G + ... + G
    $$$
    
Our implementation of Diffie-Hellman uses primes between 16 and 32 bits because of the speed at which they can be calculated is much faster than what would be needed for a real-world secure system. They work well for demonstrating the underlying concept quickly. 
    
Because we also need to factor $p-1$, we are restricted in our implementation. Factoring very large primes takes too much computational effort for a classroom demonstration. 
    
Ephemeral ECDH (ECDHE)[1] is a variant of elliptic curve Diffie-Hellman key exchange that generates a temporary DH key for every connection, therefore ensuring a key is never used twice. This is in contrast to a standard Diffie-Hellman exchange, where the private keys are reused. 

The reason ECDHE is used is to allow for what's known as "forward secrecy," or the concept that if the long-term private key of the server gets leaked, past communication is still secure [1]. Using fresh keys ensures that previous messages are still secure after a leak. 
    
While ECDH is a great scheme to ensure no brute force attacks, without authentication in the form of digital signatures, it is vulnerable to Man in the Middle attacks. This is when an adversary is able to disrupt communications between two parties by eavesdropping on their communications and potentially claiming to be someone else. 
    
While this implementation is good for demonstration purposes, real world production applications use established protocols, validated parameters, and cryptographically secure libraries because real data is on the line and researchers have determined baselines for what is considered secure to use. 

[1] "Why use Ephemeral Diffie-Hellman: Ephemeral Diffie-Hellman vs static Diffie-Hellman", Mbed TLS, https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/ephemeral-diffie-hellman/.

[2] Gregg Lindemulder and Matthew Kosinski, "What is a man-in-the-middle (MITM) attack?", IBM, https://www.ibm.com/think/topics/man-in-the-middle. 

