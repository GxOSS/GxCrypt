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

use super::Result;
use xecrypt::symmetric;

/// SHA-1 state structure for ExCrypt compatibility
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExCryptShaState {
    pub count: u32,
    pub state: [u32; 5],
    pub buffer: [u8; 64],
}

/// HMAC-SHA state structure for ExCrypt compatibility  
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExCryptHmacShaState {
    pub sha_state: [ExCryptShaState; 2],
}

/// Compute HMAC-SHA1 using XeCrypt SHA
pub fn hmac_sha(key: &[u8], inputs: &[&[u8]]) -> Result<[u8; 20]> {
    let mut inner_pad = [0u8; 64];
    let mut outer_pad = [0u8; 64];
    let key_len = key.len().min(64);
    inner_pad[..key_len].copy_from_slice(&key[..key_len]);
    outer_pad[..key_len].copy_from_slice(&key[..key_len]);

    // XOR with ipad (0x36) and opad (0x5C)
    for byte in &mut inner_pad {
        *byte ^= 0x36;
    }
    for byte in &mut outer_pad {
        *byte ^= 0x5C;
    }

    // Build inner input: inner_pad || inputs
    let mut inner_input = inner_pad.to_vec();
    for input in inputs.iter().take(3) {
        inner_input.extend_from_slice(input);
    }
    let inner_hash = symmetric::xe_crypt_sha(&inner_input);

    // Build outer input: outer_pad || inner_hash
    let mut outer_input = outer_pad.to_vec();
    outer_input.extend_from_slice(&inner_hash);
    let output = symmetric::xe_crypt_sha(&outer_input);

    Ok(output)
}

/// Compute RotSum+SHA (XeCryptRotSumSha)
pub fn rot_sum_sha(input1: &[u8], input2: &[u8]) -> Result<[u8; 20]> {
    let hash = symmetric::xe_crypt_rot_sum_sha(input1, input2);
    Ok(hash)
}

/// Compute SHA1 hash of up to 3 inputs using XeCrypt SHA
pub fn sha(inputs: &[&[u8]]) -> Result<[u8; 20]> {
    // Concatenate inputs and compute SHA-1
    let mut data = Vec::new();
    for input in inputs.iter().take(3) {
        data.extend_from_slice(input);
    }
    Ok(symmetric::xe_crypt_sha(&data))
}

/// Calculate SMC hash (rolling checksum)
pub fn calculate_smc_hash(data: &[u8]) -> [u8; 16] {
    let mut s0: u64 = 0;
    let mut s1: u64 = 0;
    for chunk in data.chunks_exact(4) {
        let val = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
        s0 = s0.wrapping_add(val);
        s1 = s1.wrapping_sub(val);
        s0 = s0.rotate_left(29);
        s1 = s1.rotate_left(31);
    }
    let mut hash = [0u8; 16];
    hash[0..8].copy_from_slice(&s0.to_be_bytes());
    hash[8..16].copy_from_slice(&s1.to_be_bytes());
    hash
}
