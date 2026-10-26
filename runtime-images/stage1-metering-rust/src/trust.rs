use rustls::RootCertStore;
use sha2::{Digest, Sha256};

pub const TRUST_SOURCE: &str = "webpki-roots=1.0.11";
pub const TRUST_SOURCE_SHA256: &str =
    "sha256:f5f280bbb2b287bc8e7de7e3852945a0ff50d1bbcb5ed42b6c7a568c546df171";
pub const TRUST_ROOTS_SHA256: &str =
    "sha256:b48d5407902ced1e0577fd6bff2e8ecbf5230c58100d1b67a25ea9d7075bbc7c";

pub fn production_roots() -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

pub fn roots_digest() -> String {
    let mut hash = Sha256::new();
    for root in webpki_roots::TLS_SERVER_ROOTS {
        for field in [
            Some(root.subject.as_ref()),
            Some(root.subject_public_key_info.as_ref()),
            root.name_constraints.as_ref().map(AsRef::as_ref),
        ] {
            match field {
                Some(bytes) => {
                    hash.update([1]);
                    hash.update((bytes.len() as u32).to_be_bytes());
                    hash.update(bytes);
                }
                None => hash.update([0]),
            }
        }
    }
    format!("sha256:{:x}", hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_source_and_nonempty_static_trust_set() {
        assert_eq!(
            production_roots().len(),
            webpki_roots::TLS_SERVER_ROOTS.len()
        );
        assert!(production_roots().len() > 100);
        assert_eq!(TRUST_SOURCE, "webpki-roots=1.0.11");
        assert_eq!(TRUST_SOURCE_SHA256.len(), 71);
        assert_eq!(roots_digest(), TRUST_ROOTS_SHA256);
    }
}
