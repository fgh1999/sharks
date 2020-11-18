use core::ops::{Add, Div, Mul, Sub};
use core::iter::{Sum, Product};
use super::share::Share;

pub trait SecretType: 'static + Add + Div + Sub + Mul + Sum + Product + Mul<u8> + From<u8> 
{
    /// Inner type of SecretType
    type Inner;

    /// Get a clone of inner
    fn get_inner(&self) -> Self::Inner;

    /// Get the multiplication identity element of this type
    fn get_mul_identity_elem() -> Self;

    /// Get the addition identity element of this type
    fn get_add_identity_elem() -> Self;

    fn deal<R: rand::Rng> (
        threshold: u8,
        secret: &[Self::Inner],
        rng: &mut R,
    ) -> Box<dyn Iterator<Item = Share<Self>>>;

    /// Finds the [root of the Lagrange polynomial](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach).
    /// The expected `shares` argument format is the same as the output by the `get_evaluator´ function.
    /// Where each (key, value) pair corresponds to one share, where the key is the `x` and the value is a vector of `y`,
    /// where each element corresponds to one of the secret's byte chunks.
    fn interpolate(shares: &[Share<Self>]) -> Vec<Self::Inner>;

    /// Generates `k` polynomial coefficients, being the last one `s` and the others randomly generated between `[1, 255]`.
    /// Coefficient degrees go from higher to lower in the returned vector order.
    fn random_polynomial<R: rand::Rng>(s: Self, k: u8, rng: &mut R) -> Vec<Self>;

    /// Returns an iterator over the points of the `polys` polynomials passed as argument.
    /// Each item of the iterator is a tuple `(x, [f_1(x), f_2(x)..])` where eaxh `f_i` is the result for the ith polynomial.
    /// Each polynomial corresponds to one byte chunk of the original secret.
    /// The iterator will start at `x = 1` and end at `x = 255`.
    /// 
    /// ploys: Vec<Vec<GF256>>
    ///
    /// ..., ..., s[0] // fronter, heavier weight it owned $x^(k-1), ..., x^0$
    /// ..., ..., s[1]
    ///      ...
    /// ..., ..., s[i]
    ///      ...
    /// ..., ..., s[n]
    ///
    /// where `...` here means some random integer in $[1, 255]$. `s[i]` means GF256(the ith byte of secret) 
    fn get_evaluator(polys: Vec<Vec<Self>>) -> Box<dyn Iterator<Item = Share<Self>>>;

    /// Returns the `x`th share
    /// where `x` starts from 1 to 255.
    /// (Return `Err` when `x` exceeds this limitation.)
    fn get_xth_share(ploys: &Vec<Vec<Self>>, x: u8) -> Result<Share<Self>, &'static str>;
}

pub mod finite_field;
pub mod rational;