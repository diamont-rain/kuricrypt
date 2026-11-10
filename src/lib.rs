use aes::cipher::typenum::Unsigned;
use aes::cipher::{
    array::Array, consts::U16, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, KeyInit,
    ParBlocks,
};
use aes::{Aes256Dec, Aes256Enc};
use pyo3::buffer::PyUntypedBuffer;
use pyo3::exceptions::{PyBufferError, PyValueError};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyBytesMethods, PyModule};
use std::{ptr, slice};

type AesBlock = Array<u8, U16>;

const GIL_RELEASE_MIN: usize = 2048;
const DIRECT_OUTPUT_MIN: usize = 64 * 1024;

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

enum Input<'a> {
    Bytes(&'a [u8]),
    Buffer(PyUntypedBuffer),
}

impl<'a> Input<'a> {
    fn get(value: &'a Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(bytes) = value.cast_exact::<PyBytes>() {
            return Ok(Self::Bytes(bytes.as_bytes()));
        }
        Ok(Self::Buffer(contiguous_buffer(value)?))
    }

    fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Buffer(buffer) => buffer.len_bytes(),
        }
    }

    fn copy_to(self, output: &mut [u8]) {
        match self {
            Self::Bytes(bytes) => output.copy_from_slice(bytes),
            Self::Buffer(buffer) if !output.is_empty() => {
                // The export pins the contiguous source for this copy.
                unsafe {
                    ptr::copy_nonoverlapping(
                        buffer.buf_ptr().cast::<u8>(),
                        output.as_mut_ptr(),
                        output.len(),
                    );
                }
            }
            Self::Buffer(_) => {}
        }
    }

    fn with_output<'py, R>(
        self,
        py: Python<'py>,
        work: impl FnOnce(&mut [u8]) -> PyResult<R>,
    ) -> PyResult<(Bound<'py, PyBytes>, R)> {
        let len = self.len();
        debug_assert!(len >= DIRECT_OUTPUT_MIN);

        // A NULL source allocates private, uninitialized bytes. Initialize every byte
        // before creating the mutable slice, and keep the object private until work ends.
        let (output, bytes) = unsafe {
            let object = ffi::PyBytes_FromStringAndSize(ptr::null(), len as ffi::Py_ssize_t);
            let output = Bound::from_owned_ptr_or_err(py, object)?.cast_into_unchecked::<PyBytes>();
            let bytes = ffi::PyBytes_AsString(output.as_ptr()).cast::<u8>();
            if bytes.is_null() {
                return Err(PyErr::fetch(py));
            }
            match self {
                Self::Bytes(input) => ptr::copy_nonoverlapping(input.as_ptr(), bytes, len),
                Self::Buffer(buffer) => {
                    ptr::copy_nonoverlapping(buffer.buf_ptr().cast::<u8>(), bytes, len);
                }
            }
            (output, slice::from_raw_parts_mut(bytes, len))
        };
        let result = work(bytes)?;
        Ok((output, result))
    }

    fn read_fixed<const N: usize>(&self, name: &str) -> PyResult<[u8; N]> {
        if self.len() != N {
            let unit = if N == 1 { "byte" } else { "bytes" };
            return Err(PyValueError::new_err(format!(
                "{name} size must be exactly {N} {unit}"
            )));
        }
        match self {
            Self::Bytes(bytes) => Ok((*bytes).try_into().expect("validated buffer size")),
            // The export pins the contiguous source and the size was checked above.
            Self::Buffer(buffer) => Ok(unsafe { buffer.buf_ptr().cast::<[u8; N]>().read() }),
        }
    }
}

fn process_data<T: Send, R: Send>(
    py: Python<'_>,
    data: Input<'_>,
    prepare: impl FnOnce(usize) -> PyResult<T>,
    work: impl FnOnce(&mut [u8], T) -> R + Send,
) -> PyResult<(Py<PyBytes>, R)> {
    let len = data.len();
    if len >= DIRECT_OUTPUT_MIN {
        return process_large_data(py, data, prepare, work);
    }
    let mut result = None;
    let process = |output: &mut [u8], args| {
        result = Some(maybe_detach(py, len, || work(output, args)));
        Ok(())
    };
    let output = match data {
        Input::Bytes(input) => {
            let args = prepare(len)?;
            PyBytes::new_with(py, len, |output| {
                output.copy_from_slice(input);
                process(output, args)
            })
        }
        Input::Buffer(_) => PyBytes::new_with(py, len, |output| {
            // Snapshot the input before invoking the other buffer exporters.
            data.copy_to(output);
            process(output, prepare(len)?)
        }),
    }?;
    Ok((output.unbind(), result.expect("output was processed")))
}

#[inline(never)]
fn process_large_data<T: Send, R: Send>(
    py: Python<'_>,
    data: Input<'_>,
    prepare: impl FnOnce(usize) -> PyResult<T>,
    work: impl FnOnce(&mut [u8], T) -> R + Send,
) -> PyResult<(Py<PyBytes>, R)> {
    let len = data.len();
    let args = match &data {
        Input::Bytes(_) => Ok(prepare(len)?),
        Input::Buffer(_) => Err(prepare),
    };
    let (output, result) = data.with_output(py, |output| {
        // Snapshot buffer input before invoking the other buffer exporters.
        let args = match args {
            Ok(args) => args,
            Err(prepare) => prepare(len)?,
        };
        Ok(maybe_detach(py, len, || work(output, args)))
    })?;
    Ok((output.unbind(), result))
}

fn write_buffer(value: &Bound<'_, PyAny>, bytes: &[u8]) -> PyResult<()> {
    if value.cast_exact::<PyBytes>().is_ok() {
        return Ok(());
    }
    let buffer = contiguous_buffer(value)?;
    if !buffer.readonly() && buffer.len_bytes() == bytes.len() {
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.buf_ptr().cast::<u8>(), bytes.len());
        }
    }
    Ok(())
}

#[allow(clippy::manual_is_multiple_of)]
fn check_block_data(len: usize) -> PyResult<()> {
    if len == 0 {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if len % 16 != 0 {
        return Err(PyValueError::new_err(
            "Data size must match a multiple of 16 bytes",
        ));
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

        let (blocks, _) = self.data.as_chunks_mut::<16>();
        for chunk in blocks {
            let plain = u128::from_ne_bytes(*chunk);
            let mut block = AesBlock::from((plain ^ previous_cipher).to_ne_bytes());
            backend.encrypt_block_inplace(&mut block);
            let encrypted = u128::from_ne_bytes(block.into());
            let output = encrypted ^ previous_plain;
            *chunk = output.to_ne_bytes();
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

        let (blocks, _) = self.data.as_chunks_mut::<16>();
        for chunk in blocks {
            let cipher = u128::from_ne_bytes(*chunk);
            let mut block = AesBlock::from((cipher ^ previous_cipher).to_ne_bytes());
            backend.decrypt_block_inplace(&mut block);
            let decrypted = u128::from_ne_bytes(block.into()) ^ previous_plain;
            *chunk = decrypted.to_ne_bytes();
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
        let mut counter_value = u128::from_be_bytes(*counter);
        for group in &mut groups {
            let (chunks, _) = group.as_chunks_mut::<16>();
            let mut streams: ParBlocks<B> = Default::default();
            for stream in streams.iter_mut() {
                *stream = AesBlock::from(counter_value.to_be_bytes());
                counter_value = counter_value.wrapping_add(1);
            }
            backend.encrypt_par_blocks_inplace(&mut streams);
            for (chunk, stream) in chunks.iter_mut().zip(streams.iter()) {
                *chunk = (u128::from_ne_bytes(*chunk) ^ u128::from_ne_bytes((*stream).into()))
                    .to_ne_bytes();
            }
        }
        *counter = counter_value.to_be_bytes();

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
        let (blocks, _) = self.data.as_chunks_mut::<16>();
        for chunk in blocks {
            let plain = u128::from_ne_bytes(*chunk);
            let mut block = AesBlock::from((plain ^ chain).to_ne_bytes());
            backend.encrypt_block_inplace(&mut block);
            chain = u128::from_ne_bytes(block.into());
            *chunk = chain.to_ne_bytes();
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
    let (output, ()) = process_data(
        py,
        Input::get(&data)?,
        |len| {
            let key = Input::get(&key)?;
            let iv = Input::get(&iv)?;
            check_block_data(len)?;
            Ok((key.read_fixed::<32>("Key")?, iv.read_fixed::<32>("IV")?))
        },
        |output, (key, iv)| ige(output, &key, &iv, encrypt),
    )?;
    Ok(output)
}

#[pyfunction(signature = (data, key, iv, /))]
fn ige256_encrypt(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    ige_call(py, data, key, iv, true)
}

#[pyfunction(signature = (data, key, iv, /))]
fn ige256_decrypt(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    ige_call(py, data, key, iv, false)
}

fn ctr_call(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
    state: Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let (output, (counter, state_byte)) = process_data(
        py,
        Input::get(&data)?,
        |len| {
            let key = Input::get(&key)?;
            let iv = Input::get(&iv)?;
            let state = Input::get(&state)?;
            if len == 0 {
                return Err(PyValueError::new_err("Data must not be empty"));
            }
            let key = key.read_fixed::<32>("Key")?;
            let counter = iv.read_fixed::<16>("IV")?;
            let [state] = state.read_fixed::<1>("State")?;
            if state > 15 {
                return Err(PyValueError::new_err(
                    "State value must be in the range [0, 15]",
                ));
            }
            Ok((key, counter, state))
        },
        |output, (key, mut counter, mut state)| {
            ctr(output, &key, &mut counter, &mut state);
            (counter, state)
        },
    )?;
    write_buffer(&iv, &counter)?;
    write_buffer(&state, &[state_byte])?;
    Ok(output)
}

#[pyfunction(signature = (data, key, iv, state, /))]
fn ctr256_encrypt(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
    state: Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    ctr_call(py, data, key, iv, state)
}

#[pyfunction(signature = (data, key, iv, state, /))]
fn ctr256_decrypt(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
    state: Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    ctr_call(py, data, key, iv, state)
}

fn cbc_call(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
    encrypt: bool,
) -> PyResult<Py<PyBytes>> {
    let (output, chain) = process_data(
        py,
        Input::get(&data)?,
        |len| {
            let key = Input::get(&key)?;
            let iv = Input::get(&iv)?;
            check_block_data(len)?;
            Ok((key.read_fixed::<32>("Key")?, iv.read_fixed::<16>("IV")?))
        },
        |output, (key, mut chain)| {
            cbc(output, &key, &mut chain, encrypt);
            chain
        },
    )?;
    write_buffer(&iv, &chain)?;
    Ok(output)
}

#[pyfunction(signature = (data, key, iv, /))]
fn cbc256_encrypt(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    cbc_call(py, data, key, iv, true)
}

#[pyfunction(signature = (data, key, iv, /))]
fn cbc256_decrypt(
    py: Python<'_>,
    data: Bound<'_, PyAny>,
    key: Bound<'_, PyAny>,
    iv: Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    cbc_call(py, data, key, iv, false)
}

// Raw access to Python buffers relies on the GIL during input copies and writeback.
#[pymodule(gil_used = true)]
fn kuricrypt(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(ige256_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(ige256_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(ctr256_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(ctr256_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(cbc256_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(cbc256_decrypt, module)?)?;
    Ok(())
}
