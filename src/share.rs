use alloc::vec::Vec;

#[cfg(feature = "fuzzing")]
use arbitrary::Arbitrary;

/// A share used to reconstruct the secret.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(Arbitrary, Debug))]
pub struct Share<S> {
    /// indicates that this is the xth share: the parameter of ploynomial `f_i(x)` in `self.y`.
    pub x: u8,

    /// `[f_1(x), f_2(x)..]` where eaxh `f_i(x)` is the result for the ith polynomial.
    pub y: Vec<S>,
}

/// Obtains a byte vector from a `Share` instance
impl<S: serde::Serialize> From<&Share<S>> for Vec<u8> {
    fn from(s: &Share<S>) -> Vec<u8> {
        rmp_serde::to_vec(s).unwrap()
    }
}

/// Obtains a `Share` instance from a byte slice
impl<'de, S: serde::Deserialize<'de>> core::convert::TryFrom<&'de [u8]> for Share<S> {
    type Error = &'static str;

    fn try_from(s: &'de [u8]) -> Result<Share<S>, Self::Error> {
        match rmp_serde::from_read_ref(s) {
            Ok(val) => Ok(val),
            Err(e) => Err(Box::leak(Box::new(e.to_string())))
        }
    }
}

#[cfg(test)]
mod share_test {
    use alloc::{vec};
    use core::convert::TryFrom;


    mod gf256_share_test {
        use super::{vec, TryFrom};
        use crate::secret_type::GF256;
        use crate::share::Share;

        #[test]
        fn serde_gf256_share() {
            let share = Share {
                x: 1,
                y: vec![GF256(2), GF256(3)],
            };
            let bytes = Vec::from(&share);
            let deser_result: Share<GF256> = Share::try_from(&bytes[..]).unwrap();
            assert_eq!(share, deser_result);
        }
    }

    mod rational_share_test {
        use super::{vec, TryFrom};
        use crate::secret_type::Rational;
        use crate::share::Share;

        #[test]
        fn serde_rational_share() {
            let share = Share {
                x: 1,
                y: vec![Rational::from(2), Rational::from(3)],
            };
            let bytes = Vec::from(&share);
            let deser_result: Share<Rational> = Share::try_from(&bytes[..]).unwrap();
            assert_eq!(share, deser_result);
        }
    }
}