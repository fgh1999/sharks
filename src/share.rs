use alloc::vec::Vec;
use super::secret_type::SecretType;

#[cfg(feature = "fuzzing")]
use arbitrary::Arbitrary;

/// A share used to reconstruct the secret.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(Arbitrary, Debug))]
pub struct Share<S: SecretType> {
    /// indicates that this is the xth share: the parameter of ploynomial `f_i(x)` in `self.y`.
    pub x: u8,

    /// `[f_1(x), f_2(x)..]` where eaxh `f_i(x)` is the result for the ith polynomial.
    pub y: Vec<S>,
}

// TODO: Share<_> from & to bytes