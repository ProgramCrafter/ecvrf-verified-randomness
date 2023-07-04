from tonsdk.boc import Builder as begin_cell
from base64 import b64encode
from tonsdk.boc import Cell
import hashlib
from rbcl import *


challenge_len = 128
challenge_mod = 2**128
rist255_order = 2**252 + 27742317777372353535851937790883648493

def generate_challenge(y: bytes, h: bytes, gamma: bytes, u: bytes, v: bytes) -> int:
    return int.from_bytes(begin_cell()
        .store_bytes(y)
        .store_bytes(h)
        .store_bytes(gamma)
        .store_ref(begin_cell().store_bytes(u).store_bytes(v).end_cell())
        .end_cell()
        .bytes_hash(), 'big') % challenge_mod

def generate_nonce(secret: int, h_point: bytes) -> int:
    secret_hash = begin_cell().store_uint(secret, 256).end_cell().bytes_hash()
    return int.from_bytes(begin_cell()
        .store_uint(
            int.from_bytes(secret_hash, 'big') >> 128,
            128
        )
        .store_bytes(h_point)
        .end_cell()
        .bytes_hash(), 'big') % rist255_order

def prove(secret: int, alpha: bytes) -> Cell:
    secret_bytes = secret.to_bytes(crypto_core_ristretto255_SCALARBYTES, 'little')
    public_key = crypto_scalarmult_ristretto255_base(secret_bytes)
    hf = hashlib.sha512(
        hashlib.sha256(b"ton.experimental.ratelance.ecvrf").digest()
      + alpha
      + hashlib.sha256(b"ecvrf.encodecurve.back").digest()
    ).digest()
    h = crypto_core_ristretto255_from_hash(hf)
    gamma = crypto_scalarmult_ristretto255(secret_bytes, h)
    k = generate_nonce(secret, h)
    k_bytes = k.to_bytes(crypto_core_ristretto255_SCALARBYTES, 'little')
    c = generate_challenge(public_key, h, gamma,
        crypto_scalarmult_ristretto255_base(k_bytes),
        crypto_scalarmult_ristretto255(k_bytes, h))
    s = (k + c * secret) % rist255_order
    return (begin_cell()
        .store_bytes(gamma)
        .store_uint(c, challenge_len)
        .store_uint(s, 256)
        .end_cell())


if __name__ == '__main__':
    try:
        assert crypto_core_ristretto255_SCALARBYTES * 8 == 256
        
        pi = prove(62965164, b'AB86418916')
        print('ECVRF for secret 62965164 and alpha AB86418916:')
        print(' ', pi.to_boc(False).hex())
    except:
        import traceback
        traceback.print_exc()
    finally:
        input('...')
