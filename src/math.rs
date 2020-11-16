// A module which contains necessary algorithms to compute Shamir's shares and recover secrets

use alloc::vec::Vec;

use rand::distributions::{Distribution, Uniform};

use super::field::GF256;
use super::share::Share;

// Finds the [root of the Lagrange polynomial](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach).
// The expected `shares` argument format is the same as the output by the `get_evaluator´ function.
// Where each (key, value) pair corresponds to one share, where the key is the `x` and the value is a vector of `y`,
// where each element corresponds to one of the secret's byte chunks.
pub fn interpolate(shares: &[Share]) -> Vec<u8> {
    (0..shares[0].y.len())
        .map(|s| {
            shares
                .iter()
                .map(|s_i| {
                    shares
                        .iter()
                        .filter(|s_j| s_j.x != s_i.x)
                        .map(|s_j| s_j.x / (s_j.x - s_i.x))
                        .product::<GF256>()
                        * s_i.y[s]
                })
                .sum::<GF256>()
                .0
        })
        .collect()
}

// Generates `k` polynomial coefficients, being the last one `s` and the others randomly generated between `[1, 255]`.
// Coefficient degrees go from higher to lower in the returned vector order.
pub fn random_polynomial<R: rand::Rng>(s: GF256, k: u8, rng: &mut R) -> Vec<GF256> {
    let k = k as usize;
    let mut poly = Vec::with_capacity(k);
    let between = Uniform::new_inclusive(1, 255);

    for _ in 1..k {
        poly.push(GF256(between.sample(rng)));
    }
    poly.push(s);

    poly
}

// Returns an iterator over the points of the `polys` polynomials passed as argument.
// Each item of the iterator is a tuple `(x, [f_1(x), f_2(x)..])` where eaxh `f_i` is the result for the ith polynomial.
// Each polynomial corresponds to one byte chunk of the original secret.
// The iterator will start at `x = 1` and end at `x = 255`.
// 
// ploys: Vec<Vec<GF256>>
// ```
// ..., ..., s[0] // fronter, heavier weight it owned $x^(k-1), ..., x^0$
// ..., ..., s[1]
//      ...
// ..., ..., s[i]
//      ...
// ..., ..., s[n]
// ```
// where `...` here means some random integer in $[1, 255]$. `s[i]` means GF256(the ith byte of secret) 
pub fn get_evaluator(polys: Vec<Vec<GF256>>) -> impl Iterator<Item = Share> {
    (1..=u8::max_value()).map(GF256).map(move |x| Share {
        x,
        y: polys.iter()
            .map(|p| p.iter().fold(GF256(0), |acc, c| acc * x + *c)) // figure out the result of f_i
            .collect(),
    })
}

/// Returns the `x`th share
/// where `x` starts from 1 to 255.
/// (Return `Err` when `x` exceeds this limitation.)
pub fn get_xth_share(ploys: &Vec<Vec<GF256>>, x: u8) -> Result<Share, &'static str> {
    if x == 0 {
        return Err("x cannot be 0");
    }

    let x = GF256(x);
    Ok(Share {
        x,
        y: ploys.iter()
            .map(|p| p.iter().fold(GF256(0), |acc, c| acc * x + *c)) // figure out the result of f_i
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::{get_evaluator, interpolate, random_polynomial, Share, GF256, get_xth_share};
    use alloc::{vec, vec::Vec};
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn random_polynomial_works() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
        let poly = random_polynomial(GF256(1), 3, &mut rng);
        assert_eq!(poly.len(), 3);
        assert_eq!(poly[2], GF256(1));
    }

    #[test]
    fn evaluator_works() {
        let iter = get_evaluator(vec![vec![GF256(3), GF256(2), GF256(5)]]);
        let values: Vec<_> = iter.take(2).map(|s| (s.x, s.y)).collect();
        assert_eq!(
            values,
            vec![(GF256(1), vec![GF256(4)]), (GF256(2), vec![GF256(13)])]
        );
    }

    #[test]
    fn interpolate_works() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
        let poly = random_polynomial(GF256(185), 10, &mut rng);
        let iter = get_evaluator(vec![poly]);
        let shares: Vec<Share> = iter.take(10).collect();
        let root = interpolate(&shares);
        assert_eq!(root, vec![185]);
    }

    #[test]
    fn get_xth_share_works() {
        let polys = vec![vec![GF256(3), GF256(2), GF256(5)]];
        let value_1 = get_xth_share(&polys, 1);
        let value_2 = get_xth_share(&polys, 2);
        assert_eq!(value_1.unwrap(), Share {
            x: GF256(1),
            y: vec![GF256(4)]
        });
        assert_eq!(value_2.unwrap(), Share {
            x: GF256(2),
            y: vec![GF256(13)]
        });
    }
}
