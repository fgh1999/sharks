//! Fast, small and secure [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) library crate
//!
//! Usage example (std):
//! ```
//! use sharks::{ Sharks, Share, SecretSharingOperation };
//! use sharks::secret_type::finite_field::GF256;
//!
//! // Construct a **mutable** new sharks
//! let mut sharks = Sharks::new();
//! // Obtain an iterator over the shares for secret [1, 2, 3, 4] with a threshold of 10
//! # #[cfg(feature = "std")]
//! # {
//! let dealer = sharks.dealer(10, &[1, 2, 3, 4]);
//! // Get 10 shares
//! let shares: Vec<Share<GF256>> = dealer.take(10).collect();
//! // Recover the original secret!
//! let secret = sharks.recover(shares).unwrap();
//! assert_eq!(secret, vec![1, 2, 3, 4]);
//! # }
//! ```
//!
//! Usage example (no std):
//! ```
//! use sharks::{ Sharks, Share, SecretSharingOperation };
//! use rand_chacha::rand_core::SeedableRng;
//! use sharks::secret_type::finite_field::GF256;
//!
//! // Construct a **mutable** new sharks
//! let mut sharks = Sharks::new();
//! // Obtain an iterator over the shares for secret [1, 2, 3, 4] with a threshold of 10
//! let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
//! let dealer = sharks.dealer_rng(10, &[1, 2, 3, 4], &mut rng);
//! // Get 10 shares
//! let shares: Vec<Share<GF256>> = dealer.take(10).collect();
//! // Recover the original secret!
//! let secret = sharks.recover(shares).unwrap();
//! assert_eq!(secret, vec![1, 2, 3, 4]);
//! ```
#![cfg_attr(not(feature = "std"), no_std)]

pub mod secret_type;
mod share;

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use hashbrown::HashSet;

use secret_type::SecretType;
pub use share::Share;

/// Tuple struct which implements methods to generate shares and recover secrets over a 256 bits Galois Field.
/// Its only parameter is the minimum shares threshold.
///
/// Usage example:
/// ```
/// # use sharks::{ Sharks, Share, SecretSharingOperation };
/// # use sharks::secret_type::finite_field::GF256;
/// // Construct a **mutable** new sharks
/// let mut sharks = Sharks::new();
/// // Obtain an iterator over the shares for secret [1, 2, 3, 4] with a threshold of 10
/// # #[cfg(feature = "std")]
/// # {
/// let dealer = sharks.dealer(10, &[1, 2, 3, 4]);
/// // Get 10 shares
/// let shares: Vec<Share<GF256>> = dealer.take(10).collect();
/// // Recover the original secret!
/// let secret = sharks.recover(shares).unwrap();
/// assert_eq!(secret, vec![1, 2, 3, 4]);
/// # }
/// ```
pub struct Sharks {
    pub threshold: u8,
}

impl Sharks {
    pub fn new() -> Sharks {
        Sharks { threshold: u8::MIN }
    }
}

/// Operations used in Secrect Sharing
pub trait SecretSharingOperation<S: SecretType> {
    /// This method is useful when `std` is not available. For typical usage
    /// see the `dealer` method.
    ///
    /// Given a `secret` byte slice, returns an `Iterator` along new shares.
    /// The maximum number of shares that can be generated is 256.
    /// A random number generator has to be provided.
    ///
    /// Example:
    /// ```
    /// # use sharks::{ Sharks, Share, SecretSharingOperation };
    /// # use rand_chacha::rand_core::SeedableRng;
    /// # use sharks::secret_type::finite_field::GF256;
    /// # let mut sharks = Sharks::new();
    /// // Obtain an iterator over the shares for secret [1, 2] with a threshold of 3
    /// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// let dealer = sharks.dealer_rng(3, &[1, 2], &mut rng);
    /// // Get 3 shares
    /// let shares: Vec<Share<GF256>> = dealer.take(3).collect();
    fn dealer_rng<R: rand::Rng>(
        &mut self,
        threshold: u8,
        secret: &[S::Inner],
        rng: &mut R,
    ) -> Box<dyn Iterator<Item = Share<S>>>;

    /// Given a `secret` byte slice, returns an `Iterator` along new shares.
    /// The maximum number of shares that can be generated is 256.
    ///
    /// Example:
    /// ```
    /// # use sharks::{ Sharks, Share, secret_type::finite_field::GF256, SecretSharingOperation };
    /// # let mut sharks = Sharks::new();
    /// // Obtain an iterator over the shares for secret [1, 2] with a threshold of 3
    /// let dealer = sharks.dealer(3, &[1, 2]);
    /// // Get 3 shares
    /// let shares: Vec<Share<GF256>> = dealer.take(3).collect();
    #[cfg(feature = "std")]
    fn dealer(&mut self, threshold: u8, secret: &[S::Inner]) -> Box<dyn Iterator<Item = Share<S>>>;

    /// Given an iterable collection of shares, recovers the original secret.
    /// If the number of distinct shares is less than the minimum threshold an `Err` is returned,
    /// otherwise an `Ok` containing the secret.
    ///
    /// Example:
    /// ```
    /// # use sharks::{ Sharks, Share, SecretSharingOperation, secret_type::finite_field::GF256 };
    /// # use rand_chacha::rand_core::SeedableRng;
    /// # let mut sharks = Sharks::new();
    /// # let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// # let mut shares: Vec<Share<GF256>> = sharks.dealer_rng(3, &[1], &mut rng).take(3).collect();
    /// // Recover original secret from shares
    /// let mut secret = sharks.recover(shares.clone());
    /// // Secret correctly recovered
    /// assert!(secret.is_ok());
    /// // Remove shares for demonstration purposes
    /// shares.clear();
    /// secret = sharks.recover(shares);
    /// // Not enough shares to recover secret
    /// assert!(secret.is_err());
    fn recover<T>(&self, shares: T) -> Result<Vec<S::Inner>, &str>
    where
        T: IntoIterator<Item = Share<S>>,
        T::IntoIter: Iterator<Item = Share<S>>;
}

impl<S: SecretType> SecretSharingOperation<S> for Sharks {
    fn dealer_rng<R: rand::Rng>(
        &mut self,
        threshold: u8,
        secret: &[S::Inner],
        rng: &mut R,
    ) -> Box<dyn Iterator<Item = Share<S>>> {
        self.threshold = threshold;
        S::deal(threshold, secret, rng)
    }

    #[cfg(feature = "std")]
    fn dealer(&mut self, threshold: u8, secret: &[S::Inner]) -> Box<dyn Iterator<Item = Share<S>>> {
        let mut rng = rand::thread_rng();
        self.dealer_rng(threshold, secret, &mut rng)
    }

    fn recover<T>(&self, shares: T) -> Result<Vec<S::Inner>, &str>
    where
        T: IntoIterator<Item = Share<S>>,
        T::IntoIter: Iterator<Item = Share<S>>,
    {
        let mut share_length: Option<usize> = None;
        let mut keys: HashSet<u8> = HashSet::new();
        let mut values: Vec<Share<S>> = Vec::new();

        for share in shares.into_iter() {
            if share_length.is_none() {
                share_length = Some(share.y.len());
            }

            if Some(share.y.len()) != share_length {
                return Err("All shares must have the same length");
            } else {
                keys.insert(share.x);
                values.push(share);
            }
        }

        if keys.is_empty() || (keys.len() < self.threshold as usize) {
            Err("Not enough shares to recover original secret")
        } else {
            Ok(S::interpolate(&values))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ SecretSharingOperation, Share, Sharks };
    use alloc::{ vec, vec::Vec };

    mod gf256_integration_test {
        use super::{ vec, SecretSharingOperation, Share, Sharks, Vec };
        use crate::secret_type::finite_field::GF256;

        impl Sharks {
            #[cfg(not(feature = "std"))]
            fn make_gf256_shares(&self, threshold: u8, secret: &[u8]) -> impl Iterator<Item = Share> {
                use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
                let mut rng = ChaCha8Rng::from_seed([0x90; 32]);
                self.dealer_rng(threshold, secret, &mut rng)
            }
            #[cfg(feature = "std")]
            fn make_gf256_shares(
                &mut self,
                threshold: u8,
                secret: &[u8],
            ) -> impl Iterator<Item = Share<GF256>> {
                self.dealer(threshold, &secret)
            }
        }
        #[test]
        fn test_insufficient_shares_err() {
            let mut sharks = Sharks::new();
            let shares: Vec<Share<GF256>> = sharks.make_gf256_shares(255, &[1]).take(254).collect();
            let secret = sharks.recover(shares);
            assert!(secret.is_err());
        }
        #[test]
        fn test_duplicate_shares_err() {
            let mut sharks = Sharks::new();
            let mut shares: Vec<Share<GF256>> = sharks.make_gf256_shares(255, &[1]).take(255).collect();
            shares[1] = Share {
                x: shares[0].x,
                y: shares[0].y.clone(),
            };
            let secret = sharks.recover(shares);
            assert!(secret.is_err());
        }
        #[test]
        fn test_integration_works() {
            let mut sharks = Sharks::new();
            let shares: Vec<Share<GF256>> =
                sharks.make_gf256_shares(255, &[1, 2, 3, 4]).take(255).collect();
            let secret = sharks.recover(shares).unwrap();
            assert_eq!(secret, vec![1, 2, 3, 4]);
        }
    }

    mod rational_integration_test {
        use super::{ vec, SecretSharingOperation, Share, Sharks, Vec };
        use crate::secret_type::rational::Rational;
        use num_rational::BigRational;
        use num_traits::cast::FromPrimitive;

        impl Sharks {
            #[cfg(not(feature = "std"))]
            fn make_rational_shares(&self, threshold: u8, secret: &[f64]) -> impl Iterator<Item = Share> {
                use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

                let mut rng = ChaCha8Rng::from_seed([0x90; 32]);
                self.dealer_rng(threshold, secret, &mut rng)
            }

            #[cfg(feature = "std")]
            fn make_rational_shares(
                &mut self,
                threshold: u8,
                secret: &[BigRational],
            ) -> impl Iterator<Item = Share<Rational>> {
                self.dealer(threshold, &secret)
            }
        }

        #[test]
        fn test_insufficient_shares_err() {
            let mut sharks = Sharks::new();
            let secret = vec![BigRational::from_u64(1).unwrap()];
            let shares: Vec<Share<Rational>> = sharks.make_rational_shares(10, &secret).take(9).collect();
            let secret = sharks.recover(shares);
            assert!(secret.is_err());
        }

        #[test]
        fn test_duplicate_shares_err() {
            let mut sharks = Sharks::new();
            let secret = vec![BigRational::from_u64(1).unwrap()];
            let mut shares: Vec<Share<Rational>> = sharks.make_rational_shares(10, &secret).take(10).collect();
            shares[1] = Share {
                x: shares[0].x,
                y: shares[0].y.clone(),
            };
            let secret = sharks.recover(shares);
            assert!(secret.is_err());
        }

        #[test]
        fn test_integration_works() {
            let mut sharks = Sharks::new();
            let secret_ans = vec![
                BigRational::from_u64(2).unwrap(), BigRational::from_f64(0.32423).unwrap()];
            let shares: Vec<Share<Rational>> =
                sharks.make_rational_shares(10, &secret_ans).take(10).collect();
            let secret_res = sharks.recover(shares).unwrap();
            assert!(secret_res.iter().zip(secret_ans.iter()).all(
                |(res, ans)| *res == *ans
            ));
        }
    }
}
