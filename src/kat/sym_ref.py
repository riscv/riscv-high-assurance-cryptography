"""Optional independent reference: the openssl command line.  lib(cipher, mode, key, iv, data, enc) -> bytes, or None when
openssl or the algorithm is missing (callers then skip the differential check).  mode: ECB CBC CFB CFB8 CFB1 OFB CTR."""
import subprocess
def lib(cipher, mode, key, iv, data, enc=True):
    name = ('sm4' if cipher == 'SM4' else 'aes-%d' % (8 * len(key))) + '-' + mode.lower()
    cmd = ['openssl', 'enc', '-' + name, '-K', key.hex(), '-nopad', '-e' if enc else '-d']
    if mode != 'ECB': cmd += ['-iv', iv.hex()]
    try: r = subprocess.run(cmd, input=data, capture_output=True, timeout=30)
    except Exception: return None
    return r.stdout if r.returncode == 0 else None
