//! This module implements high-level Rust bindings for silent payments

use core::ffi::c_void;
use core::fmt;

use core::mem::transmute;
#[cfg(feature = "std")]
use std;

use core;

use secp256k1_sys::{secp256k1_silentpayments_recipient_create_output_pubkey, secp256k1_silentpayments_recipient_create_shared_secret, secp256k1_silentpayments_recipient_public_data_create, secp256k1_silentpayments_recipient_public_data_parse, secp256k1_silentpayments_recipient_public_data_serialize, secp256k1_silentpayments_recipient_scan_outputs, secp256k1_silentpayments_sender_create_outputs, SilentpaymentsLabelLookupFunction};

use crate::ffi::{self, CPtr};
use crate::{constants, Keypair, PublicKey, SecretKey, XOnlyPublicKey};
use crate::Secp256k1;
use crate::Verification;

fn copy_to_ffi_pubkey(pubkey: &PublicKey) -> ffi::PublicKey {

    unsafe {
        // Get a pointer to the inner ffi::PublicKey
        let ffi_pubkey_ptr: *const ffi::PublicKey = pubkey.as_c_ptr();
        
        // Dereference the pointer to get the ffi::PublicKey
        // Then create a copy of it
        (*ffi_pubkey_ptr).clone()
    }
}


/// Struct to store recipient data
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SilentpaymentsRecipient(ffi::SilentpaymentsRecipient);

impl SilentpaymentsRecipient {

    /// Get a new SilentpaymentsRecipient
    pub fn new(scan_pubkey: &PublicKey,  spend_pubkey: &PublicKey, index: usize) -> Self {

        Self(ffi::SilentpaymentsRecipient::new(
            &copy_to_ffi_pubkey(scan_pubkey),
            &copy_to_ffi_pubkey(spend_pubkey),
            index
        ))
    }
}

/// Sender Output creation errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum SenderOutputCreationError {
    /// Unexpected failures
    Failure,
}

#[cfg(feature = "std")]
impl std::error::Error for SenderOutputCreationError {}

impl fmt::Display for SenderOutputCreationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SenderOutputCreationError::Failure => write!(f, "Failed to create silent payments outputs"),
        }
    }
}

/// Create Silent Payment outputs for recipient(s).
pub fn silentpayments_sender_create_outputs<C: Verification>(
    secp: &Secp256k1<C>,
    recipients: &mut [&SilentpaymentsRecipient],
    smallest_outpoint: &[u8; 36],
    taproot_seckeys: Option<&[&Keypair]>,
    plain_seckeys: Option<&[&SecretKey]>,
) -> Result<Vec<XOnlyPublicKey>, SenderOutputCreationError> {
    let cx = secp.ctx().as_ptr();
    let n_tx_outputs = recipients.len();

    unsafe {
        let mut out_pubkeys = vec![ffi::XOnlyPublicKey::new(); n_tx_outputs];
        let mut out_pubkeys_ptrs: Vec<_> = out_pubkeys.iter_mut().map(|k| k as *mut _).collect();

        for (i, pubkey) in out_pubkeys.iter_mut().enumerate() {
            out_pubkeys_ptrs[i] = pubkey as *mut _;
        }

        let ffi_recipients_ptrs: &mut [*const ffi::SilentpaymentsRecipient] =
                    transmute::<&mut [&SilentpaymentsRecipient], &mut [*const ffi::SilentpaymentsRecipient]>(recipients);

        let (ffi_taproot_seckeys, n_taproot_seckeys) = match taproot_seckeys {
            Some(keys) => {
                let ffi_keys: &[*const ffi::Keypair] = transmute::<&[&Keypair], &[*const ffi::Keypair]>(taproot_seckeys.unwrap());
                (ffi_keys.as_c_ptr(), keys.len())
            }
            None => (core::ptr::null(), 0),
        };

        let (ffi_plain_seckeys, n_plain_seckeys) = match plain_seckeys {
            Some(keys) => {
                let ffi_keys: &[*const u8] = transmute::<&[&SecretKey], &[*const u8]>(plain_seckeys.unwrap());
                (ffi_keys.as_c_ptr(), keys.len())
            }
            None => (core::ptr::null(), 0),
        };

        let res = secp256k1_silentpayments_sender_create_outputs(
            cx,
            out_pubkeys_ptrs.as_mut_ptr(),
            ffi_recipients_ptrs.as_mut_ptr(),
            n_tx_outputs,
            smallest_outpoint.as_ptr(),
            ffi_taproot_seckeys,
            n_taproot_seckeys,
            ffi_plain_seckeys,
            n_plain_seckeys,
        );

        if res == 1 {
            Ok(out_pubkeys.into_iter().map(XOnlyPublicKey::from).collect())
        } else {
            Err(SenderOutputCreationError::Failure)
        }
    }
}

/// Struct to store label tweak result
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LabelTweakResult {
    /// Public key
    pub pubkey: PublicKey,
    /// Label tweak
    pub label_tweak: [u8; 32],
}

/// Label tweak errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum LabelTweakError {
    /// Unexpected failures
    Failure,
}

#[cfg(feature = "std")]
impl std::error::Error for LabelTweakError {}

impl fmt::Display for LabelTweakError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            LabelTweakError::Failure => write!(f, "Failed to create label tweak"),
        }
    }
}

/// Create Silent Payment label tweak and label.
pub fn silentpayments_recipient_create_label_tweak<C: Verification>(
    secp: &Secp256k1<C>,
    recipient_scan_key: &SecretKey,
    m: u32,
) -> Result<LabelTweakResult, LabelTweakError> {

    let cx = secp.ctx().as_ptr();
    unsafe {

        let mut pubkey = ffi::PublicKey::new();
        let mut label_tweak32 = [0u8; 32];

        let res = ffi::secp256k1_silentpayments_recipient_create_label_tweak(
            cx,
            &mut pubkey,
            label_tweak32.as_mut_c_ptr(),
            recipient_scan_key.as_c_ptr(),
            m,
        );

        if res == 1 {
            let pubkey = PublicKey::from(pubkey);
            let label_tweak = label_tweak32;

            return Ok(LabelTweakResult { pubkey, label_tweak });
        } else {
            return Err(LabelTweakError::Failure);
        }
    }
}

/// Struct to store public data
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SilentpaymentsPublicData(ffi::SilentpaymentsPublicData);

impl CPtr for SilentpaymentsPublicData {
    type Target = ffi::SilentpaymentsPublicData;

    /// Obtains a const pointer suitable for use with FFI functions.
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    /// Obtains a mutable pointer suitable for use with FFI functions.
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

/// Label tweak errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum SilentpaymentsPublicDataError {
    /// Failed to create the public data
    CreationFailure,
    /// Serialization Failure
    SerializationFailure,
    /// Parse Failure
    ParseFailure,
    /// Failed to create the shared secret
    SharedSecretFailure
}

#[cfg(feature = "std")]
impl std::error::Error for SilentpaymentsPublicDataError {}

impl fmt::Display for SilentpaymentsPublicDataError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SilentpaymentsPublicDataError::SerializationFailure => write!(f, "Failed to serialize silent payments public data"),
            SilentpaymentsPublicDataError::ParseFailure => write!(f, "Failed to parse silent payments public data"),
            SilentpaymentsPublicDataError::SharedSecretFailure => write!(f, "Failed to create shared secret"),
            SilentpaymentsPublicDataError::CreationFailure => write!(f, "Failed to create silent payments public data"),
        }
    }
}

impl SilentpaymentsPublicData {
    /// Create a new `SilentpaymentsPublicData` object.
    pub fn new() -> SilentpaymentsPublicData {
        let empty_data = [0u8; constants::SILENT_PAYMENTS_PUBLIC_DATA_SIZE];
        SilentpaymentsPublicData(ffi::SilentpaymentsPublicData::from_array(empty_data))
    }

    /// Compute Silent Payment public data from input public keys and transaction inputs
    pub fn create<C: Verification>(
        secp: &Secp256k1<C>,
        smallest_outpoint: &[u8; 36],
        xonly_pubkeys: Option<&[&XOnlyPublicKey]>,
        plain_pubkeys: Option<&[&PublicKey]>,
    ) -> Result<Self, SilentpaymentsPublicDataError> {

        let cx = secp.ctx().as_ptr();

        unsafe {
            
            let empty_data = [0u8; constants::SILENT_PAYMENTS_PUBLIC_DATA_SIZE];
            let mut silentpayments_public_data = ffi::SilentpaymentsPublicData::from_array(empty_data);

            let (ffi_xonly_pubkeys, n_xonly_pubkeys) = match xonly_pubkeys {
                Some(keys) => {
                    let ffi_keys: &[*const ffi::XOnlyPublicKey] = transmute::<&[&XOnlyPublicKey], &[*const ffi::XOnlyPublicKey]>(xonly_pubkeys.unwrap());
                    (ffi_keys.as_c_ptr(), keys.len())
                }
                None => (core::ptr::null(), 0),
            };

            let (ffi_plain_pubkeys, n_plain_pubkeys) = match plain_pubkeys {
                Some(keys) => {
                    let ffi_keys: &[*const ffi::PublicKey] = transmute::<&[&PublicKey], &[*const ffi::PublicKey]>(plain_pubkeys.unwrap());
                    (ffi_keys.as_c_ptr(), keys.len())
                }
                None => (core::ptr::null(), 0),
            };

            let res = secp256k1_silentpayments_recipient_public_data_create(
                cx,
                &mut silentpayments_public_data,
                smallest_outpoint.as_c_ptr(),
                ffi_xonly_pubkeys,
                n_xonly_pubkeys,
                ffi_plain_pubkeys,
                n_plain_pubkeys,
            );

            if res == 1 {
                let silentpayments_public_data = SilentpaymentsPublicData(silentpayments_public_data);
                Ok(silentpayments_public_data)
            } else {
                Err(SilentpaymentsPublicDataError::CreationFailure)
            }
        }
    }

    /// Serialize a `silentpayments_public_data object`` into a 33-byte sequence.
    pub fn serialize<C: Verification>(&self,
        secp: &Secp256k1<C>) -> Result<[u8; 33], SilentpaymentsPublicDataError> {

        let mut output33 = [0u8; 33];

        let res = unsafe {
            secp256k1_silentpayments_recipient_public_data_serialize(
                secp.ctx().as_ptr(),
                output33.as_mut_c_ptr(),
                self.as_c_ptr(),
            )
        };

        if res == 1 {
            Ok(output33)
        } else {
            Err(SilentpaymentsPublicDataError::SerializationFailure)
        }
    }

    /// Parse a 33-byte sequence into a silent_payments_public_data object.
    pub fn parse<C: Verification>(secp: &Secp256k1<C>, input33: &[u8; 33]) -> Result<Self, SilentpaymentsPublicDataError> {

        let empty_data = [0u8; constants::SILENT_PAYMENTS_PUBLIC_DATA_SIZE];
        let mut silentpayments_public_data = ffi::SilentpaymentsPublicData::from_array(empty_data);

        let res = unsafe {
            secp256k1_silentpayments_recipient_public_data_parse(
                secp.ctx().as_ptr(),
                &mut silentpayments_public_data,
                input33.as_c_ptr(),
            )
        };

        if res == 1 {
            let silentpayments_public_data = SilentpaymentsPublicData(silentpayments_public_data);
            Ok(silentpayments_public_data)
        } else {
            Err(SilentpaymentsPublicDataError::ParseFailure)
        }
    }

    /// Create Silent Payment shared secret.
    pub fn recipient_create_shared_secret<C: Verification>(&self, secp: &Secp256k1<C>, recipient_scan_key: &SecretKey) -> Result<[u8; 33], SilentpaymentsPublicDataError> {
        let mut output33 = [0u8; 33];

        let res = unsafe {
            secp256k1_silentpayments_recipient_create_shared_secret(
                secp.ctx().as_ptr(),
                output33.as_mut_c_ptr(),
                recipient_scan_key.as_c_ptr(),
                self.as_c_ptr(),
            )
        };

        if res == 1 {
            Ok(output33)
        } else {
            Err(SilentpaymentsPublicDataError::SharedSecretFailure)
        }
    }
}

/// Found outputs struct
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SilentpaymentsFoundOutput(ffi::SilentpaymentsFoundOutput);

impl CPtr for SilentpaymentsFoundOutput {
    type Target = ffi::SilentpaymentsFoundOutput;

    /// Obtains a const pointer suitable for use with FFI functions.
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    /// Obtains a mutable pointer suitable for use with FFI functions.
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

impl fmt::Display for SilentpaymentsFoundOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        let pubkey = XOnlyPublicKey::from(self.0.output.clone());

        let buffer_str = pubkey.serialize()
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();

        write!(f, "{}", buffer_str)
    }
}

impl SilentpaymentsFoundOutput {
    /// Create a new `SilentpaymentsFoundOutput` object from a ffi::SilentpaymentsFoundOutput.
    pub fn empty() -> SilentpaymentsFoundOutput {
        SilentpaymentsFoundOutput(ffi::SilentpaymentsFoundOutput::empty())
    }
}

/// Output scan errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum OutputScanError {
    /// Unexpected failures
    Failure,
}

#[cfg(feature = "std")]
impl std::error::Error for OutputScanError {}

impl fmt::Display for OutputScanError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            OutputScanError::Failure => write!(f, "Failed to scan outputs"),
        }
    }
}

/// Scan for Silent Payment transaction outputs.
pub fn silentpayments_recipient_scan_outputs<
    C: Verification,
    F: FnMut(&[u8; 33]) -> Option<[u8; 32]>,
>(
    secp: &Secp256k1<C>,
    tx_outputs: &[&XOnlyPublicKey],
    recipient_scan_key: &SecretKey,
    public_data: &SilentpaymentsPublicData,
    recipient_spend_pubkey: &PublicKey,
    label_lookup: Option<F>,
) -> Result<Vec<SilentpaymentsFoundOutput>, OutputScanError> {
    let cx = secp.ctx().as_ptr();

    let n_tx_outputs = tx_outputs.len();

    let mut out_found_output = vec![ffi::SilentpaymentsFoundOutput::empty(); n_tx_outputs];
    let mut out_found_output_ptrs: Vec<_> = out_found_output.iter_mut().map(|k| k as *mut _).collect();

    let mut n_found_outputs: usize = 0;

    type Context<F> = (F, [u8; 32]);
    // must live for as long as the c function `secp256k1_silentpayments_recipient_scan_outputs`
    let mut context: Context<F>;
    let (label_lookup, label_context): (SilentpaymentsLabelLookupFunction, _) =
        if let Some(label_lookup) = label_lookup {
            unsafe extern "C" fn callback<F: FnMut(&[u8; 33]) -> Option<[u8; 32]>>(
                label33: *const u8,
                label_context: *const c_void,
            ) -> *const u8 {
                let label33 = unsafe { &*label33.cast::<[u8; 33]>() };
                // `.cast_mut()` requires slightly higher (1.65) msrv :(, using `as` instead.
                let (f, storage) =
                    unsafe { &mut *(label_context as *mut c_void).cast::<Context<F>>() };

                // `catch_unwind` is needed on Rust < 1.81 to prevent unwinding across an ffi
                // boundary, which is undefined behavior. When the user supplied function panics,
                // we abort the process. This behavior is consistent with Rust >= 1.81.
                match std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| f(label33))) {
                    Ok(Some(tweak)) => {
                        // We can't return a pointer to `tweak` as that lives in this function's
                        // (the callback) stack frame, `storage`, on the other hand, remains valid
                        // for the duration of secp256k1_silentpayments_recipient_scan_outputs.
                        *storage = tweak;
                        storage.as_ptr()
                    }
                    Ok(None) => core::ptr::null(),
                    Err(_) => {
                        std::process::abort();
                    }
                }
            }

            context = (label_lookup, [0; 32]);

            (callback::<F>, &mut context as *mut Context<F> as *const c_void)
        } else {
            // TODO we actually want a null pointer, but secp256k1-sys does not allow that (why?).
            // A noop is equivalent to null here, but secp256k1 has to do a bit of extra work.
            unsafe extern "C" fn noop(
                _label33: *const u8,
                _label_context: *const c_void,
            ) -> *const u8 {
                core::ptr::null()
            }

            // TODO `label_context` may be null iff `label_lookup` is null, I requested to remove
            // that requirement.
            // See https://github.com/bitcoin-core/secp256k1/pull/1519#discussion_r1748595895
            (noop, 1usize as *const c_void)
            // (core::ptr::null(), core::ptr::null())
        };

    let res = unsafe {
        let ffi_tx_outputs: &[*const ffi::XOnlyPublicKey] = transmute::<&[&XOnlyPublicKey], &[*const ffi::XOnlyPublicKey]>(tx_outputs);

        secp256k1_silentpayments_recipient_scan_outputs(
            cx,
            out_found_output_ptrs.as_mut_c_ptr(),
            &mut n_found_outputs,
            ffi_tx_outputs.as_c_ptr(),
            n_tx_outputs,
            recipient_scan_key.as_c_ptr(),
            public_data.as_c_ptr(),
            recipient_spend_pubkey.as_c_ptr(),
            label_lookup,
            label_context,
        )
    };

    if res == 1 {

        let mut result = vec![SilentpaymentsFoundOutput::empty(); n_found_outputs];
        
        for i in 0..n_found_outputs {
            result[i] = SilentpaymentsFoundOutput(out_found_output[i]);

        }
        
        Ok(result)
    } else {
        Err(OutputScanError::Failure)
    }
}

/// Output scan errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum OutputPubkeyError {
    /// Failed to create output pubkey
    CreationFailure,
}

#[cfg(feature = "std")]
impl std::error::Error for OutputPubkeyError {}

impl fmt::Display for OutputPubkeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            OutputPubkeyError::CreationFailure => write!(f, "Failed to create output pubkey"),
        }
    }
}

/// Create Silent Payment output public key.
pub fn silentpayments_recipient_create_output_pubkey(
    secp: &Secp256k1<crate::All>,
    shared_secret33: &[u8; 33],
    recipient_spend_pubkey: &PublicKey,
    k: u32,
) -> Result<XOnlyPublicKey, OutputPubkeyError> {

    let cx = secp.ctx().as_ptr();
    unsafe {

        let mut pubkey = ffi::XOnlyPublicKey::new();

        let res = secp256k1_silentpayments_recipient_create_output_pubkey(
            cx,
            &mut pubkey,
            shared_secret33.as_c_ptr(),
            recipient_spend_pubkey.as_c_ptr(),
            k,
        );

        if res == 1 {
            let pubkey = XOnlyPublicKey::from(pubkey);
            Ok(pubkey)
        } else {
            Err(OutputPubkeyError::CreationFailure)
        }
    }
}

/// Output scan errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum LabelledSpendPubkeyError {
    /// Failed to create output pubkey
    CreationFailure,
}

#[cfg(feature = "std")]
impl std::error::Error for LabelledSpendPubkeyError {}

impl fmt::Display for LabelledSpendPubkeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            LabelledSpendPubkeyError::CreationFailure => write!(f, "Failed to create labelled spend pubkey"),
        }
    }
}

/// Create Silent Payment labelled spend public key.
pub fn silentpayments_recipient_create_labelled_spend_pubkey(
    secp: &Secp256k1<crate::All>,
    recipient_spend_pubkey: &PublicKey,
    label: &PublicKey,
) -> Result<PublicKey, LabelledSpendPubkeyError> {

    let cx = secp.ctx().as_ptr();
    unsafe {

        let mut pubkey = ffi::PublicKey::new();

        let res = ffi::secp256k1_silentpayments_recipient_create_labelled_spend_pubkey(
            cx,
            &mut pubkey,
            recipient_spend_pubkey.as_c_ptr(),
            label.as_c_ptr(),
        );

        if res == 1 {
            let pubkey = PublicKey::from(pubkey);
            Ok(pubkey)
        } else {
            Err(LabelledSpendPubkeyError::CreationFailure)
        }
    }
}
