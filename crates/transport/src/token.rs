use rand::RngCore;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const TOKEN_BYTES: usize = 32;

pub fn generate_token() -> String {
    let mut raw = Zeroizing::new([0u8; TOKEN_BYTES]);
    rand::thread_rng().fill_bytes(raw.as_mut());
    encode_b64url(raw.as_ref())
}

pub use gcoms_core::encoding::{decode_b64url, encode_b64url};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Post,
    Stream,
    Queue,
}

#[derive(Default)]
struct TokenSets {
    posts: HashSet<String>,
    streams: HashSet<String>,
    queues: HashSet<String>,
}

impl Drop for TokenSets {
    fn drop(&mut self) {
        self.posts.drain().for_each(|mut token| token.zeroize());
        self.streams.drain().for_each(|mut token| token.zeroize());
        self.queues.drain().for_each(|mut token| token.zeroize());
    }
}

impl ZeroizeOnDrop for TokenSets {}

#[derive(Default, Clone)]
pub struct TokenRegistry(Arc<RwLock<TokenSets>>);

impl ZeroizeOnDrop for TokenRegistry {}

impl TokenRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_post(&self, token: &str) {
        let mut sets = self.0.write().unwrap_or_else(|p| p.into_inner());
        if !sets.queues.contains(token) {
            sets.posts.insert(token.to_string());
        }
    }

    pub fn insert_stream(&self, token: &str) {
        let mut sets = self.0.write().unwrap_or_else(|p| p.into_inner());
        if !sets.queues.contains(token) {
            sets.streams.insert(token.to_string());
        }
    }

    pub fn insert_queue(&self, token: &str) -> bool {
        let mut sets = self.0.write().unwrap_or_else(|p| p.into_inner());
        if sets.posts.contains(token) || sets.streams.contains(token) {
            return false;
        }
        sets.queues.insert(token.to_string())
    }

    pub fn remove_post(&self, token: &str) {
        if let Some(mut token) = self
            .0
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .posts
            .take(token)
        {
            token.zeroize();
        }
    }

    pub fn remove_stream(&self, token: &str) {
        if let Some(mut token) = self
            .0
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .streams
            .take(token)
        {
            token.zeroize();
        }
    }

    pub fn remove_queue(&self, token: &str) {
        if let Some(mut token) = self
            .0
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .queues
            .take(token)
        {
            token.zeroize();
        }
    }

    pub fn kind(&self, token: &str) -> Option<TokenKind> {
        let sets = self.0.read().unwrap_or_else(|p| p.into_inner());
        if sets.queues.contains(token) {
            Some(TokenKind::Queue)
        } else if sets.posts.contains(token) {
            Some(TokenKind::Post)
        } else if sets.streams.contains(token) {
            Some(TokenKind::Stream)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_43_chars_of_b64url() {
        let t = generate_token();
        assert_eq!(t.len(), 43);
        assert!(t
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn tokens_are_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
    }

    #[test]
    fn registry_kinds() {
        let r = TokenRegistry::new();
        let post = generate_token();
        let stream = generate_token();
        let queue = generate_token();
        r.insert_post(&post);
        r.insert_stream(&stream);
        assert!(r.insert_queue(&queue));
        assert_eq!(r.kind(&post), Some(TokenKind::Post));
        assert_eq!(r.kind(&stream), Some(TokenKind::Stream));
        assert_eq!(r.kind(&queue), Some(TokenKind::Queue));
        r.remove_post(&post);
        r.remove_stream(&stream);
        r.remove_queue(&queue);
        assert_eq!(r.kind(&post), None);
        assert_eq!(r.kind(&stream), None);
        assert_eq!(r.kind(&queue), None);
        assert_eq!(r.kind(&generate_token()), None);
    }

    #[test]
    fn queue_registration_rejects_kind_conflicts() {
        let r = TokenRegistry::new();
        let token = generate_token();
        r.insert_post(&token);
        assert!(!r.insert_queue(&token));
        assert_eq!(r.kind(&token), Some(TokenKind::Post));

        let queue = generate_token();
        assert!(r.insert_queue(&queue));
        r.insert_post(&queue);
        r.insert_stream(&queue);
        assert_eq!(r.kind(&queue), Some(TokenKind::Queue));
    }

    #[test]
    fn registry_has_zeroizing_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<TokenRegistry>();
    }
}
