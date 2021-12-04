import hashlib
import hmac
import secrets
import os

class SIMBA():
    """Simple, Iterative-Math Based Algorithm"""

    enc_operations = ['*','+','^','-','//']
    dec_operations = enc_operations[::-1]

    def __init__(self, random_rounds: bool = False) -> None:
        # get environment variables
        encryption_key = os.environ['SIMBA_ENCRYPTION_KEY'] if os.environ.get('SIMBA_ENCRYPTION_KEY') is not None else 'x'
        decryption_key = os.environ['SIMBA_DECRYPTION_KEY'] if os.environ.get('SIMBA_DECRYPTION_KEY') is not None else 'x'
        hmac_key = os.environ['SIMBA_HMAC_KEY'] if os.environ.get('SIMBA_HMAC_KEY') is not None else secrets.token_hex(32)

        # generate variables if none exist
        if encryption_key == 'x' or decryption_key == 'x':
            # generate random operations and numbers
            on_list = []
            for _ in range(secrets.randbelow(16) + 17):
                o = secrets.randbelow(len(self.enc_operations)-1)
                n = self.number(o)
                on_list.append({'o':o,'n':n})

            # generate encryption key
            for on in on_list:
                encryption_key = self.alg(encryption_key, on['o'], on['n'], self.enc_operations)

            # generate decryption key
            for on in reversed(on_list):
                decryption_key = self.alg(decryption_key, on['o'], on['n'], self.dec_operations)

        # set variables
        self.random_rounds = random_rounds   
        self.encryption_key = encryption_key
        self.decryption_key = decryption_key
        self.hmac_key = hmac_key

    def hmac(self, s: str):
        """Returns an HMAC signature of the encrypted message"""
        return hmac.new(self.hmac_key.encode('ascii'),
                        s.encode('ascii'),
                        hashlib.sha256).hexdigest()

    def number(self, o: int):
        """Generates a random number for the algorithm and
        adds extra complexity for certain operations"""
        n = secrets.randbelow((2**32 if o == 2 else (2**10 if (o&1) else 2**7))) + 1
        extra = f"*(-1)**(i+{secrets.randbelow(2)})" if (o&1) and secrets.randbelow(2) else ""
        return f"({n}{extra})"

    def alg(self, x: str, o: int, n: str, operations: list):
        """Returns a string representation of an algebraic equation"""
        return f"({x}{operations[o]}{n})"

    def ascii_to_bin(self, s: str):
        """Converts an ascii string to a binary string"""
        return ''.join('{:08b}'.format(i) for i in bytearray(s, 'ascii'))

    def int_to_str(self, x: int):
        """Converts an integer to a binary string and the
        converts the binary string to a text string"""
        b = format(x, 'b')
        # ensure leading zeroes are added
        b = b.zfill(len(b) + (8 - len(b) % 8))
        return ''.join([chr(int(b[i:i+8],2)) for i in range(0,len(b),8)])

    def sum_digits(self, x: int):
        """Sums the digits of an integer"""
        sum = 0
        for digit in str(x): 
            sum += int(digit)     
        return sum

    def encrypt(self, s: str):
        """Encrypts plaintext by converting the binary to a number and
        iterating that number through the encryption_key equation"""
        try:
            # convert string to int
            b = self.ascii_to_bin(s)
            x = int(b, 2)

            # iterative encryption
            rounds = secrets.randbelow(191) + 64 if self.random_rounds else (self.sum_digits(x) % 191) + 64
            for i in range(1, rounds + 1):
                x = eval(self.encryption_key)
            x = int(format(x, 'x') + format(rounds, 'x'), 16)

            # final iteration to hide rounds
            i = 1
            x = eval(self.encryption_key)
            msg = format(x, 'x')

            return msg + self.hmac(msg)
        except:
            return "Something went wrong..."

    def decrypt(self, s: str):
        """Decrypts ciphertext by iterating the number through the decryption_key
        equation and converting resulting binary number to a text string"""
        try:
            hash = s[-64:]
            sx = s[:-64]
            if self.hmac(sx) == hash:
                # decrypt final iteration to get rounds
                i = 1
                x = int(sx, 16)
                x = eval(self.decryption_key)
                sx = format(x, 'x')

                # iterative decryption
                rounds = int(sx[-2:], 16)
                x = int(sx[:-2], 16)
                for i in reversed(range(1, rounds + 1)):
                    x = eval(self.decryption_key)

                # convert to string
                return self.int_to_str(x)
            else:
                raise Exception
        except:
            return "Improperly encrypted ciphertext."

if __name__ == "main":
    pt = "This is a test message!"
    
    # test without random rounds
    s1 = SIMBA()
    ct1 = s1.encrypt(pt)
    print('W/O Random Rounds:', ct1, s1.decrypt(ct1))

    # test with random rounds
    s2 = SIMBA(True)
    # example 1
    ct2 = s2.encrypt(pt)
    print('Random Rounds 1:', ct2, s2.decrypt(ct2))
    # example 2
    ct3 = s2.encrypt(pt)
    print('Random Rounds 2:', ct3, s2.decrypt(ct3))
