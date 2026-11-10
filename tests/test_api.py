from array import array
import unittest
from typing import Any, Callable

import kuricrypt

KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
)


class TestKuricryptApi(unittest.TestCase):
    def test_cbc_nist_vector_and_mutable_iv(self):
        iv = bytearray.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        ciphertext = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")

        self.assertEqual(kuricrypt.cbc256_encrypt(plaintext, KEY, iv), ciphertext)
        self.assertEqual(iv, ciphertext)

        decrypt_iv = bytearray.fromhex("000102030405060708090a0b0c0d0e0f")
        self.assertEqual(kuricrypt.cbc256_decrypt(ciphertext, KEY, decrypt_iv), plaintext)
        self.assertEqual(decrypt_iv, ciphertext)

    def test_ctr_nist_vector_and_stream_state(self):
        iv = bytearray.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        state = bytearray([0])
        plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        ciphertext = bytes.fromhex("601ec313775789a5b7a7f504bbf3d228")

        self.assertEqual(kuricrypt.ctr256_encrypt(plaintext, KEY, iv, state), ciphertext)
        self.assertEqual(iv, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdff00"))
        self.assertEqual(state, bytearray([0]))

        iv = bytearray.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        state = bytearray([0])
        chunks = [plaintext[:5], plaintext[5:11], plaintext[11:]]
        encrypted = b"".join(
            kuricrypt.ctr256_encrypt(chunk, KEY, iv, state) for chunk in chunks
        )

        self.assertEqual(encrypted, ciphertext)
        self.assertEqual(iv, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdff00"))
        self.assertEqual(state, bytearray([0]))

    def test_ige_round_trip(self):
        data = bytes(range(64))
        iv = bytes(range(32))
        encrypted = kuricrypt.ige256_encrypt(data, KEY, iv)

        self.assertNotEqual(encrypted, data)
        self.assertEqual(kuricrypt.ige256_decrypt(encrypted, KEY, iv), data)

    def test_typed_contiguous_buffers(self):
        data = array("I", range(4))
        key = array("I", range(8))
        iv = array("I", range(8))

        actual = kuricrypt.ige256_encrypt(memoryview(data), memoryview(key), memoryview(iv))
        expected = kuricrypt.ige256_encrypt(data.tobytes(), key.tobytes(), iv.tobytes())
        self.assertEqual(actual, expected)

    def test_writable_data_view_can_alias_cbc_iv(self):
        data = bytearray(range(32))
        iv = memoryview(data)[:16]
        initial_iv = bytearray(iv)
        expected = kuricrypt.cbc256_encrypt(bytes(data), KEY, initial_iv)

        actual = kuricrypt.cbc256_encrypt(memoryview(data), KEY, iv)

        self.assertIs(type(actual), bytes)
        self.assertEqual(actual, expected)
        self.assertEqual(data, initial_iv + bytearray(range(16, 32)))

    def test_large_buffer_matches_chunked_cbc(self):
        data = bytes(range(256)) * 256
        split = len(data) // 2
        chunked_iv = bytearray(16)
        expected = kuricrypt.cbc256_encrypt(data[:split], KEY, chunked_iv)
        expected += kuricrypt.cbc256_encrypt(data[split:], KEY, chunked_iv)

        for source in (data, memoryview(bytearray(data))):
            with self.subTest(source=type(source)):
                iv = bytearray(16)
                actual = kuricrypt.cbc256_encrypt(source, KEY, iv)
                self.assertIs(type(actual), bytes)
                self.assertEqual(actual, expected)
                self.assertEqual(iv, chunked_iv)

    def test_validation_errors(self):
        cases: list[tuple[Callable[..., bytes], tuple[Any, ...], str]] = [
            (kuricrypt.ige256_encrypt, (b"", KEY, bytes(32)), "Data must not be empty"),
            (kuricrypt.ige256_encrypt, (bytes(15), KEY, bytes(32)), "multiple of 16 bytes"),
            (
                kuricrypt.cbc256_encrypt,
                (bytes(16), bytes(31), bytes(16)),
                "Key size must be exactly 32 bytes",
            ),
            (
                kuricrypt.ctr256_encrypt,
                (b"x", KEY, bytes(16), bytes([16])),
                r"range \[0, 15\]",
            ),
        ]
        for function, args, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    function(*args)
