/*
BSD 3-Clause License

Copyright (c) 2020, emoose
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

pub mod aes;
pub mod keys;
pub mod rc4;
pub mod rsa;
pub mod sha;

// Re-exports for convenient access
pub use keys::{console_sign, get_console_private_key, get_key_bytes, set_key, verify_signature};
pub use keys::{keyvault_loaded, load_keyvault, load_keyvault_from_path, XeKey};
pub use rc4::Rc4;
pub use rsa::{
    pkcs1_format, pkcs1_verify, rsa_prv_crypt, rsa_pub_crypt, sign_pkcs1v15_sha1,
    verify_pkcs1v15_sha1,
};
pub use rsa::{ExCryptRsa, ExCryptRsaPrv1024, ExCryptRsaPub1024, ExCryptRsaPub2048};
pub use sha::{calculate_smc_hash, hmac_sha, rot_sum_sha, sha};

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key size (expected {expected}, got {got})")]
    InvalidKeySize { expected: usize, got: usize },
    #[error("Invalid data size")]
    InvalidDataSize,
    #[error("Buffer too small")]
    BufferTooSmall,
}

/// Swap qword endianness (LE <-> BE)
pub fn swap_qw_endian(src: &[u64], dst: &mut [u64]) {
    let len = src.len().min(dst.len());
    for i in 0..len {
        dst[i] = src[i].swap_bytes();
    }
}
