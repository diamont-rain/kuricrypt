use aes::cipher::typenum::Unsigned;
use aes::cipher::{
    array::Array, consts::U16, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, KeyInit,
    ParBlocks,
};
use aes::{Aes256Dec, Aes256Enc};
use pyo3::buffer::PyUntypedBuffer;
use pyo3::exceptions::{PyBufferError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyBytesMethods, PyModule, PyTuple};
use std::borrow::Cow;
use std::slice;

type AesBlock = Array<u8, U16>;

const GIL_RELEASE_MIN: usize = 2048;

fn maybe_detach<T: Send>(py: Python<'_>, len: usize, work: impl FnOnce() -> T + Send) -> T {
    if len >= GIL_RELEASE_MIN {
        py.detach(work)
    } else {
        work()
    }
}

fn contiguous_buffer(value: &Bound<'_, PyAny>) -> PyResult<PyUntypedBuffer> {
    let buffer = PyUntypedBuffer::get(value)?;
    if !buffer.is_c_contiguous() {
        return Err(PyBufferError::new_err("Buffer must be contiguous"));
    }
    Ok(buffer)
}

fn read_data<'a>(value: &'a Bound<'_, PyAny>) -> PyResult<Cow<'a, [u8]>> {
    if let Ok(bytes) = value.cast_exact::<PyBytes>() {
        return Ok(Cow::Borrowed(bytes.as_bytes()));
    }
    let buffer = contiguous_buffer(value)?;
    let len = buffer.len_bytes();
    if len == 0 {
        return Ok(Cow::Borrowed(&[]));
    }
    let bytes = unsafe { slice::from_raw_parts(buffer.buf_ptr().cast::<u8>(), len) };
    Ok(Cow::Owned(bytes.to_vec()))
}

fn process_data(
    py: Python<'_>,
    data: Cow<'_, [u8]>,
    work: impl FnOnce(&mut [u8]) + Send,
) -> PyResult<Py<PyBytes>> {
    let len = data.len();
    let output = match data {
        Cow::Borrowed(input) => PyBytes::new_with(py, len, |output| {
            output.copy_from_slice(input);
            maybe_detach(py, len, || work(output));
            Ok(())
        })?,
        Cow::Owned(mut output) => {
            maybe_detach(py, len, || work(&mut output));
            PyBytes::new(py, &output)
        }
    };
    Ok(output.unbind())
}

fn read_fixed_buffer<const N: usize>(buffer: &PyUntypedBuffer, name: &str) -> PyResult<[u8; N]> {
    if buffer.len_bytes() != N {
        let unit = if N == 1 { "byte" } else { "bytes" };
        return Err(PyValueError::new_err(format!(
            "{name} size must be exactly {N} {unit}"
        )));
    }
    // The exported contiguous buffer contains exactly N bytes and stays alive during the read.
    Ok(unsafe { buffer.buf_ptr().cast::<[u8; N]>().read() })
}

fn write_buffer(value: &Bound<'_, PyAny>, bytes: &[u8]) -> PyResult<()> {
    let buffer = contiguous_buffer(value)?;
    if !buffer.readonly() && buffer.len_bytes() == bytes.len() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                buffer.buf_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
    }
    Ok(())
}

#[allow(clippy::manual_is_multiple_of)]
fn check_block_data(data: &[u8]) -> PyResult<()> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err(
            "Data size must match a multiple of 16 bytes",
        ));
    }
    Ok(())
}

fn check_arg_count(args: &Bound<'_, PyTuple>, expected: usize) -> PyResult<()> {
    if args.len() != expected {
        return Err(PyTypeError::new_err(format!(
            "function takes exactly {expected} arguments ({} given)",
            args.len()
        )));
    }
    Ok(())
}

struct IgeEncrypt<'a> {
    data: &'a mut [u8],
    iv: &'a [u8],
}

impl BlockSizeUser for IgeEncrypt<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncClosure for IgeEncrypt<'_> {
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        let mut previous_cipher = u128::from_ne_bytes(self.iv[..16].try_into().unwrap());
        let mut previous_plain = u128::from_ne_bytes(self.iv[16..].try_into().unwrap());

        for chunk in self.data.chunks_mut(16) {
            let mut plain_bytes = [0u8; 16];
            plain_bytes.copy_from_slice(chunk);
            let plain = u128::from_ne_bytes(plain_bytes);
            let mut block = AesBlock::from((plain ^ previous_cipher).to_ne_bytes());
            backend.encrypt_block_inplace(&mut block);
            let encrypted = u128::from_ne_bytes(block.into());
            let output = encrypted ^ previous_plain;
            chunk.copy_from_slice(&output.to_ne_bytes());
            previous_cipher = output;
            previous_plain = plain;
        }
    }
}

struct IgeDecrypt<'a> {
    data: &'a mut [u8],
    iv: &'a [u8],
}

impl BlockSizeUser for IgeDecrypt<'_> {
    type BlockSize = U16;
}

impl BlockCipherDecClosure for IgeDecrypt<'_> {
    fn call<B: BlockCipherDecBackend<BlockSize = U16>>(self, backend: &B) {
        let mut previous_cipher = u128::from_ne_bytes(self.iv[16..].try_into().unwrap());
        let mut previous_plain = u128::from_ne_bytes(self.iv[..16].try_into().unwrap());

        for chunk in self.data.chunks_mut(16) {
            let mut cipher_bytes = [0u8; 16];
            cipher_bytes.copy_from_slice(chunk);
            let cipher = u128::from_ne_bytes(cipher_bytes);
            let mut block = AesBlock::from((cipher ^ previous_cipher).to_ne_bytes());
            backend.decrypt_block_inplace(&mut block);
            let decrypted = u128::from_ne_bytes(block.into()) ^ previous_plain;
            chunk.copy_from_slice(&decrypted.to_ne_bytes());
            previous_cipher = decrypted;
            previous_plain = cipher;
        }
    }
}

fn ige(data: &mut [u8], key: &[u8], iv: &[u8], encrypt: bool) {
    if encrypt {
        let cipher = Aes256Enc::new_from_slice(key).expect("validated AES-256 key");
        cipher.encrypt_with_backend(IgeEncrypt { data, iv });
    } else {
        let cipher = Aes256Dec::new_from_slice(key).expect("validated AES-256 key");
        cipher.decrypt_with_backend(IgeDecrypt { data, iv });
    }
}

fn increment_counter(counter: &mut [u8; 16]) {
    *counter = u128::from_be_bytes(*counter).wrapping_add(1).to_be_bytes();
}

struct CtrProcess<'a> {
    data: &'a mut [u8],
    counter: &'a mut [u8; 16],
    state: &'a mut u8,
}

impl BlockSizeUser for CtrProcess<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncClosure for CtrProcess<'_> {
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        let data = self.data;
        let counter = self.counter;
        let state = self.state;
        let mut offset = 0;

        if *state != 0 {
            let mut stream = AesBlock::from(*counter);
            backend.encrypt_block_inplace(&mut stream);
            let stream: [u8; 16] = stream.into();
            let take = (16 - *state as usize).min(data.len());
            for index in 0..take {
                data[index] ^= stream[*state as usize + index];
            }
            offset += take;
            *state += take as u8;
            if *state == 16 {
                *state = 0;
                increment_counter(counter);
            }
            if offset == data.len() {
                return;
            }
        }

        let parallel_width = B::ParBlocksSize::USIZE;
        let mut groups = data[offset..].chunks_exact_mut(parallel_width * 16);
        for group in &mut groups {
            let mut streams: ParBlocks<B> = Default::default();
            for stream in streams.iter_mut() {
                *stream = AesBlock::from(*counter);
                increment_counter(counter);
            }
            backend.encrypt_par_blocks_inplace(&mut streams);
            for (block_index, stream) in streams.iter().enumerate() {
                let stream: [u8; 16] = (*stream).into();
                let start = block_index * 16;
                for index in 0..16 {
                    group[start + index] ^= stream[index];
                }
            }
        }

        let remainder = groups.into_remainder();
        for block in remainder.chunks_mut(16) {
            let block_len = block.len();
            let mut stream = AesBlock::from(*counter);
            backend.encrypt_block_inplace(&mut stream);
            let stream: [u8; 16] = stream.into();
            for index in 0..block_len {
                block[index] ^= stream[index];
            }
            if block_len == 16 {
                increment_counter(counter);
            } else {
                *state = block_len as u8;
            }
        }
    }
}

fn ctr(data: &mut [u8], key: &[u8], counter: &mut [u8; 16], state: &mut u8) {
    let cipher = Aes256Enc::new_from_slice(key).expect("validated AES-256 key");
    cipher.encrypt_with_backend(CtrProcess {
        data,
        counter,
        state,
    });
}

struct CbcEncrypt<'a> {
    data: &'a mut [u8],
    chain: &'a mut [u8; 16],
}

impl BlockSizeUser for CbcEncrypt<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncClosure for CbcEncrypt<'_> {
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        let mut chain = u128::from_ne_bytes(*self.chain);
        for chunk in self.data.chunks_mut(16) {
            let mut plain_bytes = [0u8; 16];
            plain_bytes.copy_from_slice(chunk);
            let plain = u128::from_ne_bytes(plain_bytes);
            let mut block = AesBlock::from((plain ^ chain).to_ne_bytes());
            backend.encrypt_block_inplace(&mut block);
            chain = u128::from_ne_bytes(block.into());
            chunk.copy_from_slice(&chain.to_ne_bytes());
        }
        *self.chain = chain.to_ne_bytes();
    }
}

struct CbcDecrypt<'a> {
    data: &'a mut [u8],
    chain: &'a mut [u8; 16],
}

impl BlockSizeUser for CbcDecrypt<'_> {
    type BlockSize = U16;
}

impl BlockCipherDecClosure for CbcDecrypt<'_> {
    fn call<B: BlockCipherDecBackend<BlockSize = U16>>(self, backend: &B) {
        let mut chain = u128::from_ne_bytes(*self.chain);
        let mut groups = self.data.chunks_exact_mut(B::ParBlocksSize::USIZE * 16);
        for group in &mut groups {
            let (chunks, _) = group.as_chunks_mut::<16>();
            let mut blocks: ParBlocks<B> = Default::default();
            for (block, chunk) in blocks.iter_mut().zip(chunks.iter()) {
                block.copy_from_slice(chunk);
            }
            backend.decrypt_par_blocks_inplace(&mut blocks);
            for (block, chunk) in blocks.iter().zip(chunks.iter_mut()) {
                let cipher = u128::from_ne_bytes(*chunk);
                let plain = u128::from_ne_bytes((*block).into()) ^ chain;
                *chunk = plain.to_ne_bytes();
                chain = cipher;
            }
        }
        let (tail, _) = groups.into_remainder().as_chunks_mut::<16>();
        for chunk in tail {
            let cipher = u128::from_ne_bytes(*chunk);
            let mut block = AesBlock::from(*chunk);
            backend.decrypt_block_inplace(&mut block);
            let plain = u128::from_ne_bytes(block.into()) ^ chain;
            *chunk = plain.to_ne_bytes();
            chain = cipher;
        }
        *self.chain = chain.to_ne_bytes();
    }
}

fn cbc(data: &mut [u8], key: &[u8], chain: &mut [u8; 16], encrypt: bool) {
    if encrypt {
        let cipher = Aes256Enc::new_from_slice(key).expect("validated AES-256 key");
        cipher.encrypt_with_backend(CbcEncrypt { data, chain });
    } else {
        let cipher = Aes256Dec::new_from_slice(key).expect("validated AES-256 key");
        cipher.decrypt_with_backend(CbcDecrypt { data, chain });
    }
}

fn ige_call(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
    encrypt: bool,
) -> PyResult<Py<PyBytes>> {
    let data = read_data(&data)?;
    let key = contiguous_buffer(&key)?;
    let iv = contiguous_buffer(&iv)?;
    check_block_data(&data)?;
    let key = read_fixed_buffer::<32>(&key, "Key")?;
    let iv = read_fixed_buffer::<32>(&iv, "IV")?;
    process_data(py, data, |output| ige(output, &key, &iv, encrypt))
}

#[pyfunction(signature = (*args))]
fn ige256_encrypt(py: Python<'_>, args: Bound<'_, PyTuple>) -> PyResult<Py<PyBytes>> {
    check_arg_count(&args, 3)?;
    ige_call(
        py,
        args.get_item(0)?,
        args.get_item(1)?,
        args.get_item(2)?,
        true,
    )
}

#[pyfunction(signature = (*args))]
fn ige256_decrypt(py: Python<'_>, args: Bound<'_, PyTuple>) -> PyResult<Py<PyBytes>> {
    check_arg_count(&args, 3)?;
    ige_call(
        py,
        args.get_item(0)?,
        args.get_item(1)?,
        args.get_item(2)?,
        false,
    )
}

fn ctr_call(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
    state: Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let data_bytes = read_data(&data)?;
    let key_buffer = contiguous_buffer(&key)?;
    let iv_buffer = contiguous_buffer(&iv)?;
    let state_buffer = contiguous_buffer(&state)?;
    if data_bytes.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    let key_bytes = read_fixed_buffer::<32>(&key_buffer, "Key")?;
    let mut iv_bytes = read_fixed_buffer::<16>(&iv_buffer, "IV")?;
    let [mut state_byte] = read_fixed_buffer::<1>(&state_buffer, "State")?;
    drop((key_buffer, iv_buffer, state_buffer));
    if state_byte > 15 {
        return Err(PyValueError::new_err(
            "State value must be in the range [0, 15]",
        ));
    }

    let output = process_data(py, data_bytes, |output| {
        ctr(output, &key_bytes, &mut iv_bytes, &mut state_byte);
    })?;
    write_buffer(&iv, &iv_bytes)?;
    write_buffer(&state, &[state_byte])?;
    Ok(output)
}

#[pyfunction]
#[pyo3(signature = (*args))]
fn ctr256_encrypt(py: Python<'_>, args: Bound<'_, PyTuple>) -> PyResult<Py<PyBytes>> {
    check_arg_count(&args, 4)?;
    ctr_call(
        py,
        args.get_item(0)?,
        args.get_item(1)?,
        args.get_item(2)?,
        args.get_item(3)?,
    )
}

#[pyfunction(signature = (*args))]
fn ctr256_decrypt(py: Python<'_>, args: Bound<'_, PyTuple>) -> PyResult<Py<PyBytes>> {
    check_arg_count(&args, 4)?;
    ctr_call(
        py,
        args.get_item(0)?,
        args.get_item(1)?,
        args.get_item(2)?,
        args.get_item(3)?,
    )
}

fn cbc_call(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
    encrypt: bool,
) -> PyResult<Py<PyBytes>> {
    let data_bytes = read_data(&data)?;
    let key_buffer = contiguous_buffer(&key)?;
    let iv_buffer = contiguous_buffer(&iv)?;
    check_block_data(&data_bytes)?;
    let key_bytes = read_fixed_buffer::<32>(&key_buffer, "Key")?;
    let mut iv_bytes = read_fixed_buffer::<16>(&iv_buffer, "IV")?;
    drop((key_buffer, iv_buffer));
    let output = process_data(py, data_bytes, |output| {
        cbc(output, &key_bytes, &mut iv_bytes, encrypt);
    })?;
    write_buffer(&iv, &iv_bytes)?;
    Ok(output)
}

#[pyfunction(signature = (*args))]
fn cbc256_encrypt(py: Python<'_>, args: Bound<'_, PyTuple>) -> PyResult<Py<PyBytes>> {
    check_arg_count(&args, 3)?;
    cbc_call(
        py,
        args.get_item(0)?,
        args.get_item(1)?,
        args.get_item(2)?,
        true,
    )
}

#[pyfunction(signature = (*args))]
fn cbc256_decrypt(py: Python<'_>, args: Bound<'_, PyTuple>) -> PyResult<Py<PyBytes>> {
    check_arg_count(&args, 3)?;
    cbc_call(
        py,
        args.get_item(0)?,
        args.get_item(1)?,
        args.get_item(2)?,
        false,
    )
}

#[pymodule]
fn kuricrypt(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(ige256_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(ige256_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(ctr256_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(ctr256_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(cbc256_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(cbc256_decrypt, module)?)?;
    Ok(())
}
