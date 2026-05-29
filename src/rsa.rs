use super::{CryptoError, Result};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that PKCS1v1.5 format produces correct output
    #[test]
    fn test_pkcs1_format_sha1() {
        let hash = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    0x99, 0xAA, 0xBB, 0xCC];
        let mut output = vec![0u8; 128]; // 1024-bit signature
        
        assert!(pkcs1_format(&hash, 0, &mut output).is_ok());
        
        // Verify structure: first bytes are reversed hash, end is 0x01, 0x00
        assert_eq!(output[0], hash[19]); // First byte should be last hash byte (reversed)
        assert_eq!(output[19], hash[0]);  // Last byte of hash region is first hash byte
        assert_eq!(output[126], 0x01);     // End marker
        assert_eq!(output[127], 0x00);     // End marker
        
        // Verify padding is 0xFF
        for i in 39..126 {
            assert_eq!(output[i], 0xFF);
        }
    }

    /// Test PKCS1v1.5 round-trip: format should produce verifiable signature
    #[test]
    fn test_pkcs1_format_verify_roundtrip() {
        let hash = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    0x99, 0xAA, 0xBB, 0xCC];
        let mut sig = vec![0u8; 128];
        
        // Format the signature
        pkcs1_format(&hash, 0, &mut sig).unwrap();
        
        // Verify it matches
        assert!(pkcs1_verify(&hash, &sig));
        
        // Verify that wrong hash fails
        let wrong_hash = [0x00; 20];
        assert!(!pkcs1_verify(&wrong_hash, &sig));
    }

    /// Test BigUint conversion round-trip
    #[test]
    fn test_biguint_conversion_roundtrip() {
        // Test data: simple pattern
        let qw: [u64; 2] = [0x0001020304050607, 0x08090A0B0C0D0E0F];
        
        // Convert to BigUint
        let bn = qw_to_biguint(&qw);
        
        // Convert back
        let result = biguint_to_qw(&bn, 2);
        
        assert_eq!(qw[0], result[0]);
        assert_eq!(qw[1], result[1]);
    }

    /// Test raw RSA public/private round-trip with known key
    #[test]
    fn test_rsa_roundtrip_with_generated_key() {
        // Generate a 1024-bit key pair for testing
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public_key = RsaPrivateKey::to_public_key(&private_key);
        
        // Create test message (128 bytes = 1024 bits)
        let message: [u8; 128] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
            0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
            0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
            0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        ];
        
        // Sign with PKCS1v15
        let signature = sign_pkcs1v15_sha1(&private_key, &message[..20]).unwrap();
        
        // Verify with public key
        assert!(verify_pkcs1v15_sha1(&public_key, &message[..20], &signature).unwrap());
    }

    /// Test ExCrypt RSA struct conversion
    #[test]
    fn test_excrypt_rsa_struct_conversions() {
        // Create a test ExCryptRsaPub1024 with 1024-bit key (16 qwords)
        let pub_key = ExCryptRsaPub1024 {
            rsa: ExCryptRsa {
                num_digits: 16, // 16 qwords = 128 bytes = 1024 bits
                pub_exponent: 65537,
                reserved: 0,
            },
            modulus: [
                0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
            ], // Valid modulus (must be odd and large enough)
        };
        
        // Should convert to RsaPublicKey
        let rsa_pub = pub_key.to_rsa_public_key();
        assert!(rsa_pub.is_ok());
    }
}
