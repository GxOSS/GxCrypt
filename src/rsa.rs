use super::{CryptoError, Result};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};

// --- Types (from excrypt.h / excrypt_bn.h) ---

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExCryptRsa {
    pub num_digits: u32,
    pub pub_exponent: u32,
    pub reserved: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExCryptRsaPub1024 {
    pub rsa: ExCryptRsa,
    pub modulus: [u64; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExCryptRsaPub2048 {
    pub rsa: ExCryptRsa,
    pub modulus: [u64; 32],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExCryptRsaPrv1024 {
    pub rsa: ExCryptRsa,
    pub modulus: [u64; 16],
    pub prime1: [u64; 8],
    pub prime2: [u64; 8],
    pub exponent1: [u64; 8],
    pub exponent2: [u64; 8],
    pub coefficient: [u64; 8],
    pub priv_exponent: [u64; 16],
}

// --- Helper functions for BigUint conversion ---

/// Convert qword array (little-endian u64) to BigUint
/// XeCrypt stores qwords in big-endian format within each u64, but the array
/// is little-endian (least significant qword first)
fn qw_to_biguint(qw: &[u64]) -> BigUint {
    let mut bytes = Vec::with_capacity(qw.len() * 8);
    // Reverse to get big-endian byte order for the whole number
    for &q in qw.iter().rev() {
        bytes.extend_from_slice(&q.to_be_bytes());
    }
    BigUint::from_bytes_be(&bytes)
}

/// Convert BigUint to qword array (little-endian u64 array)
fn biguint_to_qw(value: &BigUint, num_qwords: usize) -> Vec<u64> {
    let bytes = value.to_bytes_be();
    let mut qw = vec![0u64; num_qwords];
    
    // Pad to required size
    let mut padded_bytes = vec![0u8; num_qwords * 8];
    let start = num_qwords * 8 - bytes.len().min(num_qwords * 8);
    padded_bytes[start..start + bytes.len().min(num_qwords * 8)].copy_from_slice(&bytes);
    
    // Convert to qwords in reverse order (little-endian array)
    for (i, chunk) in padded_bytes.chunks(8).enumerate().rev() {
        let idx = num_qwords - 1 - i;
        if idx < qw.len() {
            qw[idx] = u64::from_be_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3],
                chunk[4], chunk[5], chunk[6], chunk[7]
            ]);
        }
    }
    qw
}

// --- Safe implementations of ExCrypt functions ---

/// Raw RSA private key operation: m = c^d mod n
/// Equivalent to ExCryptBnQwNeRsaPrvCrypt
pub fn rsa_prv_crypt(input: &[u64], key: &ExCryptRsaPrv1024) -> Result<Vec<u64>> {
    let num_digits = key.rsa.num_digits.swap_bytes() as usize;
    if num_digits == 0 || num_digits > 0x40 {
        return Err(CryptoError::InvalidKeySize { expected: 16, got: num_digits });
    }
    
    // Convert input to BigUint
    let c = qw_to_biguint(&input[..num_digits]);
    let n = qw_to_biguint(&key.modulus[..num_digits]);
    let d = qw_to_biguint(&key.priv_exponent[..num_digits]);
    
    // Compute m = c^d mod n
    let m = c.modpow(&d, &n);
    
    Ok(biguint_to_qw(&m, num_digits))
}

/// Raw RSA public key operation: c = m^e mod n
/// Equivalent to ExCryptBnQwNeRsaPubCrypt
pub fn rsa_pub_crypt(input: &[u64], key: &ExCryptRsaPub1024) -> Result<Vec<u64>> {
    let num_digits = key.rsa.num_digits as usize;
    let exp = key.rsa.pub_exponent as u32;
    
    // Convert input to BigUint
    let m = qw_to_biguint(&input[..num_digits]);
    let n = qw_to_biguint(&key.modulus[..num_digits]);
    let e: BigUint = exp.into();
    
    // Compute c = m^e mod n
    let c = m.modpow(&e, &n);
    
    Ok(biguint_to_qw(&c, num_digits))
}

// --- excrypt_bn_pkcs1.cpp ---

/// Format a hash into a PKCS1v1.5 signature block
/// Equivalent to ExCryptBnDwLePkcs1Format
pub fn pkcs1_format(hash: &[u8], format: u32, output: &mut [u8]) -> Result<()> {
    let output_size = output.len();
    
    if output_size < 39 || output_size - 39 > 473 {
        return Err(CryptoError::InvalidDataSize);
    }
    
    // Fill entire buffer with 0xFF
    output.fill(0xFF);
    
    // End markers
    output[output_size - 1] = 0x00;
    output[output_size - 2] = 0x01;
    
    // Copy reversed hash (20 bytes) to the START of the buffer
    if hash.len() >= 20 {
        for i in 0..20 {
            output[19 - i] = hash[i];
        }
    }
    
    // Format-specific bytes after the reversed hash
    match format {
        0 => {
            // SHA1 format bytes
            output[0x14..0x1C].copy_from_slice(&[0x14, 0x04, 0x00, 0x05, 0x1A, 0x21, 0x30, 0xE0]);
            output[0x1C..0x24].copy_from_slice(&[0x2B, 0x05, 0x06, 0x09, 0x30, 0x21, 0x00, 0x00]);
        }
        1 => {
            // SHA256 format bytes
            output[0x14..0x1C].copy_from_slice(&[0x14, 0x04, 0x1A, 0x02, 0x03, 0x0E, 0x2B, 0x05]);
            output[0x1C..0x20].copy_from_slice(&[0x06, 0x07, 0x30, 0x1F]);
            output[0x20..0x22].copy_from_slice(&[0x30, 0x00]);
        }
        2 => {
            // MD5 format
            output[0x14] = 0x00;
        }
        _ => {}
    }
    
    Ok(())
}

/// Verify a PKCS1v1.5 signature
/// Equivalent to ExCryptBnDwLePkcs1Verify
pub fn pkcs1_verify(hash: &[u8], sig: &[u8]) -> bool {
    let sig_size = sig.len();
    
    if sig_size < 39 || sig_size - 39 > 473 {
        return false;
    }
    
    // Determine format based on sig[0x16]
    let format = if sig[0x16] == 0 {
        0
    } else if sig[0x16] == 0x1A {
        1
    } else {
        2
    };
    
    // Create expected signature
    let mut test_sig = vec![0u8; sig_size];
    if pkcs1_format(hash, format, &mut test_sig).is_err() {
        return false;
    }
    
    // Compare
    test_sig == sig
}

// --- Safe wrappers ---

/// Convert ExCryptRsaPrv1024 to RsaPrivateKey
impl ExCryptRsaPrv1024 {
    pub fn to_rsa_private_key(&self) -> Result<RsaPrivateKey> {
        let num_digits = self.rsa.num_digits.swap_bytes() as usize;
        let half = num_digits / 2;
        
        let p = qw_to_biguint(&self.prime1[..half]);
        let q = qw_to_biguint(&self.prime2[..half]);
        
        RsaPrivateKey::from_p_q(
            p,
            q,
            self.rsa.pub_exponent.swap_bytes().into(),
        ).map_err(|_| CryptoError::InvalidDataSize.into())
    }
}

/// Convert ExCryptRsaPub1024 to RsaPublicKey
impl ExCryptRsaPub1024 {
    pub fn to_rsa_public_key(&self) -> Result<RsaPublicKey> {
        let num_digits = self.rsa.num_digits as usize;
        
        let n = qw_to_biguint(&self.modulus[..num_digits]);
        let e: BigUint = self.rsa.pub_exponent.into();
        
        RsaPublicKey::new(n, e).map_err(|_| CryptoError::InvalidDataSize.into())
    }
}

/// Sign data with PKCS1v1.5 padding using a private key
pub fn sign_pkcs1v15_sha1(private_key: &RsaPrivateKey, hash: &[u8]) -> Result<Vec<u8>> {
    use rsa::Pkcs1v15Sign;
    
    // SHA-1 DER prefix for PKCS1v1.5
    const SHA1_DER_PREFIX: &[u8] = &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
    
    let scheme = Pkcs1v15Sign { hash_len: Some(20), prefix: SHA1_DER_PREFIX.into() };
    
    private_key.sign(scheme, hash)
        .map_err(|_| CryptoError::InvalidDataSize.into())
}

/// Verify signature with PKCS1v1.5 padding using a public key
pub fn verify_pkcs1v15_sha1(public_key: &RsaPublicKey, hash: &[u8], sig: &[u8]) -> Result<bool> {
    use rsa::Pkcs1v15Sign;
    
    const SHA1_DER_PREFIX: &[u8] = &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
    
    let scheme = Pkcs1v15Sign { hash_len: Some(20), prefix: SHA1_DER_PREFIX.into() };
    
    match public_key.verify(scheme, hash, sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
