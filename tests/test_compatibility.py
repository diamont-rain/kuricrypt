from importlib import import_module
import unittest

import kuricrypt

try:
    tgcrypto = import_module("tgcrypto")
except ImportError:
    tgcrypto = None


KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
)


class TestTgcryptoCompatibility(unittest.TestCase):
    @unittest.skipIf(tgcrypto is None, "tgcrypto is not installed")
    def test_all_cipher_functions_match_tgcrypto(self):
        data = bytes(range(256)) * 16
        block_iv = bytes(range(32))
        stream_iv = bytes(range(16))

        for function_name in ("ige256_encrypt", "ige256_decrypt"):
            with self.subTest(function=function_name):
                reference = getattr(tgcrypto, function_name)(data, KEY, block_iv)
                actual = getattr(kuricrypt, function_name)(data, KEY, block_iv)
                self.assertEqual(actual, reference)

        for function_name in ("cbc256_encrypt", "cbc256_decrypt"):
            with self.subTest(function=function_name):
                reference_iv = bytearray(stream_iv)
                actual_iv = bytearray(stream_iv)
                reference = getattr(tgcrypto, function_name)(data, KEY, reference_iv)
                actual = getattr(kuricrypt, function_name)(data, KEY, actual_iv)
                self.assertEqual(actual, reference)
                self.assertEqual(actual_iv, reference_iv)

        stream_data = data[:-3]
        initial_state = bytearray([7])
        for function_name in ("ctr256_encrypt", "ctr256_decrypt"):
            with self.subTest(function=function_name):
                reference_iv = bytearray(stream_iv)
                actual_iv = bytearray(stream_iv)
                reference_state = bytearray(initial_state)
                actual_state = bytearray(initial_state)
                reference = getattr(tgcrypto, function_name)(
                    stream_data, KEY, reference_iv, reference_state
                )
                actual = getattr(kuricrypt, function_name)(
                    stream_data, KEY, actual_iv, actual_state
                )
                self.assertEqual(actual, reference)
                self.assertEqual(actual_iv, reference_iv)
                self.assertEqual(actual_state, reference_state)
