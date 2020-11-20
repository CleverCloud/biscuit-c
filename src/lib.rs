use rand::prelude::*;
use std::{
    ffi::CStr,
    os::raw::c_char
};

pub struct Biscuit(biscuit_auth::token::Biscuit);
pub struct KeyPair(biscuit_auth::crypto::KeyPair);
pub struct PublicKey(biscuit_auth::crypto::PublicKey);
pub struct BiscuitBuilder<'a>(biscuit_auth::token::builder::BiscuitBuilder<'a>);
pub struct Verifier<'a>(biscuit_auth::token::verifier::Verifier<'a>);

#[repr(C)]
pub struct Slice {
    ptr: *const u8,
    len: usize,
}

#[repr(C)]
pub struct Bytes {
    ptr: *mut u8,
    len: usize,
    capacity: usize,
}

impl Slice {
    fn to_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn keypair_new<'a>(
    seed: Slice,
) -> Option<Box<KeyPair>> {
    let slice = seed.to_slice();
    if slice.len() != 32 {
        return None;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(slice);

    let mut rng: StdRng = SeedableRng::from_seed(seed);

    Some(Box::new(KeyPair(biscuit_auth::crypto::KeyPair::new(&mut rng))))
}

#[no_mangle]
pub unsafe extern "C" fn keypair_public(
    kp: Option<&KeyPair>,
) -> Option<Box<PublicKey>> {
    let  kp = kp?;

    Some(Box::new(PublicKey((*kp).0.public())))
}

#[no_mangle]
pub unsafe extern "C" fn keypair_free(
    _kp: Option<Box<KeyPair>>,
) {

}

#[no_mangle]
pub unsafe extern "C" fn public_key_free(
    _kp: Option<Box<PublicKey>>,
) {
}


#[no_mangle]
pub unsafe extern "C" fn biscuit_builder<'a>(
    keypair: Option<&'a KeyPair>,
) -> Option<Box<BiscuitBuilder<'a>>> {
    let keypair = keypair?;

    Some(Box::new(BiscuitBuilder(
        biscuit_auth::token::Biscuit::builder(&keypair.0),
    )))
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_add_authority_fact<'a>(
    builder: Option<&mut BiscuitBuilder<'a>>,
    fact: *const c_char,
) -> bool {
    if builder.is_none() {
        return false;
    }
    let builder = builder.unwrap();

    let fact = CStr::from_ptr(fact);
    let s = fact.to_str();
    if s.is_err() {
        return false;
    }

    builder.0.add_authority_fact(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_add_authority_rule<'a>(
    builder: Option<&mut BiscuitBuilder<'a>>,
    rule: *const c_char,
) -> bool {
    if builder.is_none() {
        return false;
    }
    let builder = builder.unwrap();

    let rule = CStr::from_ptr(rule);
    let s = rule.to_str();
    if s.is_err() {
        return false;
    }

    builder.0.add_authority_rule(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_add_authority_caveat<'a>(
    builder: Option<&mut BiscuitBuilder<'a>>,
    caveat: *const c_char,
) -> bool {
    if builder.is_none() {
        return false;
    }
    let builder = builder.unwrap();

    let caveat = CStr::from_ptr(caveat);
    let s = caveat.to_str();
    if s.is_err() {
        return false;
    }

    builder.0.add_authority_caveat(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_build<'a>(
    builder: Option<Box<BiscuitBuilder<'a>>>,
    seed: Slice,
) -> Option<Box<Biscuit>> {
    let builder = builder?;

    let slice = seed.to_slice();
    if slice.len() != 32 {
        return None;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(slice);

    println!("building token");
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    (*builder).0.build(&mut rng).map(Biscuit).map(Box::new).ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_free<'a>(
    _builder: Option<Box<BiscuitBuilder<'a>>>,
) {
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_from(
    biscuit: Slice,
) -> Option<Box<Biscuit>> {
    let biscuit = biscuit.to_slice();

    biscuit_auth::token::Biscuit::from(biscuit).map(Biscuit).map(Box::new).ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_from_sealed(
    biscuit: Slice,
    secret: Slice,
) -> Option<Box<Biscuit>> {
    let biscuit = biscuit.to_slice();
    let secret = secret.to_slice();

    biscuit_auth::token::Biscuit::from_sealed(biscuit, secret).map(Biscuit).map(Box::new).ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_serialize(
    biscuit: Option<&Biscuit>,
) -> Bytes {
    if biscuit.is_none() {
        return Bytes {
            ptr: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        };
    }

    let biscuit = biscuit.unwrap();

    (*biscuit).0.to_vec().map(|mut v| {
        let res = Bytes {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            capacity: v.capacity(),
        };

        std::mem::forget(v);
        res
    }).unwrap_or_else(|_| {
        Bytes {
            ptr: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_serialize_sealed(
    biscuit: Option<&Biscuit>,
    secret: Slice,
) -> Bytes {
    if biscuit.is_none() {
        return Bytes {
            ptr: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        };
    }

    let biscuit = biscuit.unwrap();
    let secret = secret.to_slice();

    (*biscuit).0.seal(secret).map(|mut v| {
        let res = Bytes {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            capacity: v.capacity(),
        };

        std::mem::forget(v);
        res
    }).unwrap_or_else(|_| {
        Bytes {
            ptr: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_verify<'a, 'b>(
    biscuit: Option<&'a Biscuit>,
    root: Option<&'b PublicKey>,
) -> Option<Box<Verifier<'a>>> {
    let biscuit = biscuit?;
    let root = root?;

    (*biscuit).0.verify((*root).0).map(Verifier).map(Box::new).ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_free(
    _biscuit: Option<Box<Biscuit>>,
) {
}

#[no_mangle]
pub unsafe extern "C" fn verifier_free<'a>(
    _verifier: Option<Box<Verifier<'a>>>,
) {
}
#[no_mangle]
pub unsafe extern "C" fn bytes_free(
    bytes: Bytes,
) {
    if bytes.ptr != std::ptr::null_mut() {
        let _v = Vec::from_raw_parts(bytes.ptr, bytes.len, bytes.capacity);
    }
}

#[cfg(test)]
mod tests {
    use inline_c::assert_c;

    #[test]
    fn build() {
        //set_var("CFLAGS", "-I$CARGO_MANIFEST_DIR");
        std::env::set_var("INLINE_C_RS_CFLAGS", "-I. -L./target/debug");
        std::env::set_var("INLINE_C_RS_LDFLAGS", "-lbiscuit_c -lpthread -ldl -lm");

        (assert_c! {
            #include <stdio.h>
            #include "bindings.h"

            int main() {
                char *seed = "abcd";
                Slice s;
                s.ptr = (const uint8_t *) seed;
                s.len = sizeof(seed);

                KeyPair * root_kp = keypair_new(s);
                PublicKey* root = keypair_public(root_kp);

                BiscuitBuilder* b = biscuit_builder(root_kp);
                biscuit_builder_add_authority_fact(b, "right(#authority, \"file1\", #read)");

                Biscuit * biscuit = biscuit_builder_build(b, s);
                printf("Hello, World!\n");

                Verifier * verifier = biscuit_verify(biscuit, root);
                verifier_free(verifier);
                biscuit_free(biscuit);
                public_key_free(root);
                keypair_free(root_kp);

                return 0;
            }
        })
        .success()
        .stdout("Hello world");
    }
}
