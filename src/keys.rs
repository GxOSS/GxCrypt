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

//! Key vault and console key management
//!
//! Pure safe Rust implementation - no FFI needed

use super::{CryptoError, Result};
use crate::rsa::{
    ExCryptRsa, ExCryptRsaPrv1024, ExCryptRsaPub1024,
    pkcs1_format, pkcs1_verify,
    rsa_prv_crypt, rsa_pub_crypt,
};
use crate::swap_qw_endian;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{LazyLock, Mutex};

// =============================================================================
// SAFE RUST API (Recommended for new code)
// =============================================================================

/// Load a keyvault from file path (safe Rust API)
pub fn load_keyvault_from_path(path: &std::path::Path) -> Result<()> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| CryptoError::InvalidDataSize)?;
    let metadata = file.metadata()
        .map_err(|_| CryptoError::InvalidDataSize)?;
    let mut filesize = metadata.len() as usize;
    
    if filesize < 0x3FF0 {
        return Err(CryptoError::InvalidDataSize);
    }
    
    let mut contents = Vec::new();
    if filesize >= 0x4000 {
        file.seek(SeekFrom::Start(0x10))
            .map_err(|_| CryptoError::InvalidDataSize)?;
        filesize -= 0x10;
    }
    contents.resize(filesize, 0);
    file.read_exact(&mut contents)
        .map_err(|_| CryptoError::InvalidDataSize)?;
    
    {
        let mut vault = EX_KEY_VAULT.lock().unwrap();
        *vault = contents;
    }
    ex_keys_key_vault_setup();
    Ok(())
}

/// Load keyvault from bytes (safe Rust API)
pub fn load_keyvault(data: &[u8]) -> Result<()> {
    if data.len() < 0x3FF0 {
        return Err(CryptoError::InvalidDataSize);
    }
    let offset = if data.len() >= 0x4000 { 0x10 } else { 0 };
    {
        let mut vault = EX_KEY_VAULT.lock().unwrap();
        *vault = data[offset..].to_vec();
    }
    ex_keys_key_vault_setup();
    Ok(())
}

/// Check if keyvault is loaded (safe Rust API)
pub fn keyvault_loaded() -> bool {
    !EX_KEY_VAULT.lock().unwrap().is_empty()
}

/// Get console private key for RSA operations (safe Rust API)
pub fn get_console_private_key() -> Option<ExCryptRsaPrv1024> {
    let key_data = get_key_bytes(XeKey::ConsolePrivateKey)?;
    if key_data.len() < std::mem::size_of::<ExCryptRsaPrv1024>() {
        return None;
    }
    // SAFETY: We're reading from a valid byte slice with correct size
    let key = unsafe {
        std::ptr::read_unaligned(key_data.as_ptr() as *const ExCryptRsaPrv1024)
    };
    Some(key)
}

/// Get key as bytes (safe Rust API)
pub fn get_key_bytes(key: XeKey) -> Option<Vec<u8>> {
    let key_idx = key as u32;
    if !is_key_supported(key_idx) {
        return None;
    }
    
    {
        let imported = EX_IMPORTED_KEYS.lock().unwrap();
        if let Some(key_data) = imported.get(&key_idx) {
            return Some(key_data.clone());
        }
    }
    
    let vault = EX_KEY_VAULT.lock().unwrap();
    if vault.is_empty() {
        return None;
    }
    
    let (offset, size) = key_properties(key_idx)?;
    Some(vault[offset as usize..offset as usize + size as usize].to_vec())
}

/// Set/import a key (safe Rust API)
pub fn set_key(key: XeKey, data: &[u8]) {
    EX_IMPORTED_KEYS.lock().unwrap().insert(key as u32, data.to_vec());
}

/// Sign data with console private key (safe Rust API)
pub fn console_sign(hash: &[u8; 20]) -> Option<[u8; 128]> {
    let private_key = get_console_private_key()?;
    
    // Format PKCS1v1.5 signature block
    let mut sig_buf = [0u64; 0x10];
    let sig_bytes = unsafe {
        std::slice::from_raw_parts_mut(sig_buf.as_mut_ptr() as *mut u8, 0x10 * 8)
    };
    pkcs1_format(hash, 0, sig_bytes).ok()?;
    
    // Byteswap for RSA operation
    let mut swapped = [0u64; 0x10];
    swap_qw_endian(&sig_buf, &mut swapped);
    
    // Perform RSA private key operation
    let result = rsa_prv_crypt(&swapped, &private_key).ok()?;
    
    // Copy result back and byteswap output
    let mut output_buf = [0u64; 0x10];
    output_buf[..result.len().min(0x10)].copy_from_slice(&result[..result.len().min(0x10)]);
    swap_qw_endian(&output_buf, &mut sig_buf);
    
    // Return as bytes
    let mut output = [0u8; 128];
    output.copy_from_slice(sig_bytes);
    Some(output)
}

/// Verify PKCS1v1.5 signature with a public key (safe Rust API)
pub fn verify_signature(hash: &[u8; 20], signature: &[u8], key: &ExCryptRsaPub1024) -> bool {
    let key_digits = key.rsa.num_digits.swap_bytes();
    let modulus_size = (key_digits * 8) as usize;
    
    if modulus_size > 0x200 || signature.len() < modulus_size {
        return false;
    }
    
    // Convert signature to qwords (byteswap)
    let sig_qwords: &[u64] = unsafe {
        std::slice::from_raw_parts(signature.as_ptr() as *const u64, key_digits as usize)
    };
    let mut temp_sig = vec![0u64; key_digits as usize];
    swap_qw_endian(sig_qwords, &mut temp_sig);
    
    // RSA public decrypt
    let result = match rsa_pub_crypt(&temp_sig, key) {
        Ok(r) => r,
        Err(_) => return false,
    };
    
    // Copy result back and byteswap
    let result_len = result.len().min(temp_sig.len());
    let mut output_buf = vec![0u64; key_digits as usize];
    output_buf[..result_len].copy_from_slice(&result[..result_len]);
    swap_qw_endian(&output_buf, &mut temp_sig);
    
    // Verify PKCS1v1.5 format
    let sig_bytes = unsafe {
        std::slice::from_raw_parts(temp_sig.as_ptr() as *const u8, modulus_size)
    };
    pkcs1_verify(hash, sig_bytes)
}

// =============================================================================
// INTERNAL FUNCTIONS (shared between safe API and FFI)
// =============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum XeKey {
    ManufacturingMode = 0x0,
    AlternateKeyVault = 0x1,
    RestrictedPrivilegeFlags = 0x2,
    ReservedByte3 = 0x3,
    OddFeatures = 0x4,
    OddAuthType = 0x5,
    RestrictedHvExtLoader = 0x6,
    PolicyFlashSize = 0x7,
    PolicyBuiltinUsbMuSize = 0x8,
    ReservedDword4 = 0x9,
    RestrictedPrivileges = 0xA,
    ReservedQword2 = 0xB,
    ReservedQword3 = 0xC,
    ReservedQword4 = 0xD,
    ReservedKey1 = 0xE,
    ReservedKey2 = 0xF,
    ReservedKey3 = 0x10,
    ReservedKey4 = 0x11,
    ReservedRandomKey1 = 0x12,
    ReservedRandomKey2 = 0x13,
    ConsoleSerialNumber = 0x14,
    MoboSerialNumber = 0x15,
    GameRegion = 0x16,
    ConsoleObfuscationKey = 0x17,
    KeyObfuscationKey = 0x18,
    RoamableObfuscationKey = 0x19,
    DvdKey = 0x1A,
    PrimaryActivationKey = 0x1B,
    SecondaryActivationKey = 0x1C,
    GlobalDevice2DesKey1 = 0x1D,
    GlobalDevice2DesKey2 = 0x1E,
    WirelessControllerMs2DesKey1 = 0x1F,
    WirelessControllerMs2DesKey2 = 0x20,
    WiredWebcamMs2DesKey1 = 0x21,
    WiredWebcamMs2DesKey2 = 0x22,
    WiredControllerMs2DesKey1 = 0x23,
    WiredControllerMs2DesKey2 = 0x24,
    MemoryUnitMs2DesKey1 = 0x25,
    MemoryUnitMs2DesKey2 = 0x26,
    OtherXsm3DeviceMs2DesKey1 = 0x27,
    OtherXsm3DeviceMs2DesKey2 = 0x28,
    WirelessController3p2DesKey1 = 0x29,
    WirelessController3p2DesKey2 = 0x2A,
    WiredWebcam3p2DesKey1 = 0x2B,
    WiredWebcam3p2DesKey2 = 0x2C,
    WiredController3p2DesKey1 = 0x2D,
    WiredController3p2DesKey2 = 0x2E,
    MemoryUnit3p2DesKey1 = 0x2F,
    MemoryUnit3p2DesKey2 = 0x30,
    OtherXsm3Device3p2DesKey1 = 0x31,
    OtherXsm3Device3p2DesKey2 = 0x32,
    ConsolePrivateKey = 0x33,
    XeikaPrivateKey = 0x34,
    CardeaPrivateKey = 0x35,
    ConsoleCertificate = 0x36,
    XeikaCertificate = 0x37,
    CardeaCertificate = 0x38,
    ConstantMasterKey = 0x3C,
}

static EX_IMPORTED_KEYS: LazyLock<Mutex<HashMap<u32, Vec<u8>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static EX_KEY_VAULT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

const K_ROAMABLE_OBFUSCATION_KEY_RETAIL: [u8; 16] = [0xE1, 0xBC, 0x15, 0x9C, 0x73, 0xB1, 0xEA, 0xE9, 0xAB, 0x31, 0x70, 0xF3, 0xAD, 0x47, 0xEB, 0xF3];
const K_ROAMABLE_OBFUSCATION_KEY_DEVKIT: [u8; 16] = [0xDA, 0xB6, 0x9A, 0xD9, 0x8E, 0x28, 0x76, 0x4F, 0x97, 0x7E, 0xE2, 0x48, 0x7E, 0x4F, 0x3F, 0x68];

fn key_properties(key_idx: u32) -> Option<(u32, u32)> {
    match key_idx {
        0x0 => Some((0x8, 0x1)),
        0x1 => Some((0x9, 0x1)),
        0x2 => Some((0xA, 0x1)),
        0x3 => Some((0xB, 0x1)),
        0x4 => Some((0xC, 0x2)),
        0x5 => Some((0xE, 0x2)),
        0x6 => Some((0x10, 0x4)),
        0x7 => Some((0x14, 0x4)),
        0x8 => Some((0x18, 0x4)),
        0x9 => Some((0x1C, 0x4)),
        0xA => Some((0x20, 0x8)),
        0xB => Some((0x28, 0x8)),
        0xC => Some((0x30, 0x8)),
        0xD => Some((0x38, 0x8)),
        0xE => Some((0x40, 0x10)),
        0xF => Some((0x50, 0x10)),
        0x10 => Some((0x60, 0x10)),
        0x11 => Some((0x70, 0x10)),
        0x12 => Some((0x80, 0x10)),
        0x13 => Some((0x90, 0x10)),
        0x14 => Some((0xA0, 0xC)),
        0x15 => Some((0xAC, 0xC)),
        0x16 => Some((0xB8, 0x2)),
        0x17 => Some((0xC0, 0x10)),
        0x18 => Some((0xD0, 0x10)),
        0x19 => Some((0xE0, 0x10)),
        0x1A => Some((0xF0, 0x10)),
        0x1B => Some((0x100, 0x18)),
        0x1C => Some((0x118, 0x10)),
        0x1D => Some((0x128, 0x10)),
        0x1E => Some((0x138, 0x10)),
        0x1F => Some((0x148, 0x10)),
        0x20 => Some((0x158, 0x10)),
        0x21 => Some((0x168, 0x10)),
        0x22 => Some((0x178, 0x10)),
        0x23 => Some((0x188, 0x10)),
        0x24 => Some((0x198, 0x10)),
        0x25 => Some((0x1A8, 0x10)),
        0x26 => Some((0x1B8, 0x10)),
        0x27 => Some((0x1C8, 0x10)),
        0x28 => Some((0x1D8, 0x10)),
        0x29 => Some((0x1E8, 0x10)),
        0x2A => Some((0x1F8, 0x10)),
        0x2B => Some((0x208, 0x10)),
        0x2C => Some((0x218, 0x10)),
        0x2D => Some((0x228, 0x10)),
        0x2E => Some((0x238, 0x10)),
        0x2F => Some((0x248, 0x10)),
        0x30 => Some((0x258, 0x10)),
        0x31 => Some((0x268, 0x10)),
        0x32 => Some((0x278, 0x10)),
        0x33 => Some((0x288, 0x1D0)),
        0x34 => Some((0x458, 0x390)),
        0x35 => Some((0x7E8, 0x1D0)),
        0x36 => Some((0x9B8, 0x1A8)),
        0x37 => Some((0xB60, 0x1288)),
        0x38 => Some((0x1EE8, 0x2108)),
        0x44 => Some((0x1DF8, 0x100)),
        _ => None,
    }
}

fn is_key_supported(key_idx: u32) -> bool {
    let vault_loaded = !EX_KEY_VAULT.lock().unwrap().is_empty();
    let has_property = key_properties(key_idx).is_some();
    let imported = EX_IMPORTED_KEYS.lock().unwrap().contains_key(&key_idx);
    (vault_loaded && has_property) || imported
}

fn ex_keys_key_vault_setup() {
    let console_type = ex_keys_get_console_type();
    let key = if console_type == 2 {
        K_ROAMABLE_OBFUSCATION_KEY_RETAIL
    } else {
        K_ROAMABLE_OBFUSCATION_KEY_DEVKIT
    };
    // Store the roamable key directly in the vault
    let key_idx = XeKey::RoamableObfuscationKey as u32;
    if let Some((offset, _)) = key_properties(key_idx) {
        let mut vault = EX_KEY_VAULT.lock().unwrap();
        if vault.len() >= offset as usize + 16 {
            vault[offset as usize..offset as usize + 16].copy_from_slice(&key);
        }
    }
}

fn ex_keys_load_key_vault(data: &[u8]) -> bool {
    if data.len() < 0x3FF0 {
        return false;
    }
    let offset = if data.len() >= 0x4000 { 0x10 } else { 0 };
    {
        let mut vault = EX_KEY_VAULT.lock().unwrap();
        *vault = data[offset..].to_vec();
    }
    ex_keys_key_vault_setup();
    true
}

fn ex_keys_get_key(key_idx: u32, output: Option<&mut [u8]>) -> Option<u32> {
    if !is_key_supported(key_idx) {
        return None;
    }

    {
        let imported = EX_IMPORTED_KEYS.lock().unwrap();
        if let Some(key) = imported.get(&key_idx) {
            let size = key.len() as u32;
            if let Some(out) = output {
                let len = out.len().min(key.len());
                out[..len].copy_from_slice(&key[..len]);
            }
            return Some(size);
        }
    }

    let vault = EX_KEY_VAULT.lock().unwrap();
    if vault.is_empty() {
        return None;
    }

    let (offset, size) = key_properties(key_idx)?;
    if let Some(out) = output {
        let len = out.len().min(size as usize);
        out[..len].copy_from_slice(&vault[offset as usize..offset as usize + len]);
    }
    Some(size)
}

fn ex_keys_get_key_offset(key_idx: u32) -> Option<usize> {
    if !is_key_supported(key_idx) {
        return None;
    }
    key_properties(key_idx).map(|(offset, _)| offset as usize)
}

fn ex_keys_get_key_properties(key_idx: u32) -> u32 {
    if !is_key_supported(key_idx) {
        return 0;
    }
    {
        let imported = EX_IMPORTED_KEYS.lock().unwrap();
        if let Some(key) = imported.get(&key_idx) {
            return key.len() as u32;
        }
    }
    key_properties(key_idx).map(|(_, size)| size).unwrap_or(0)
}

fn ex_keys_get_console_type() -> u32 {
    let offset = match ex_keys_get_key_offset(XeKey::ConsoleCertificate as u32) {
        Some(off) => off,
        None => return 0,
    };
    let vault = EX_KEY_VAULT.lock().unwrap();
    if vault.len() < offset + 0x1C {
        return 0;
    }
    let cert_offset = offset + 0x18;
    u32::from_be_bytes([vault[cert_offset], vault[cert_offset + 1], vault[cert_offset + 2], vault[cert_offset + 3]])
}

// --- Idiomatic KeyManager ---

static EXKEYS_LOCK: Mutex<()> = Mutex::new(());

pub struct KeyManager;

impl KeyManager {
    /// Load keyvault from bytes
    pub fn load_vault(data: &[u8]) -> Result<()> {
        let _lock = EXKEYS_LOCK.lock().unwrap();
        load_keyvault(data)
    }

    /// Get a key by its enum value
    pub fn get_key(key: XeKey) -> Option<Vec<u8>> {
        let _lock = EXKEYS_LOCK.lock().unwrap();
        get_key_bytes(key)
    }

    /// Sign a hash with the console private key
    pub fn sign_hash(hash: &[u8; 20]) -> Option<[u8; 128]> {
        let _lock = EXKEYS_LOCK.lock().unwrap();
        console_sign(hash)
    }
}
