use core::iter::{Product, Sum};
use core::ops::{Add, Div, Mul, Sub};
use alloc::vec::Vec;
use super::SecretType;
use crate::Share;
use num_rational::BigRational;
use num_traits::cast::FromPrimitive;
use serde::{ Serialize, Deserialize };

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(Arbitrary))]
pub struct Rational {
    inner: BigRational,
}


// impl PartialEq for Float {
//     fn eq(&self, other: &Self) -> bool {
//         /// Judge if the two equals to each other within two toleratable abs and rel error
//         fn is_equal_float(a: f64, b: f64, abs_error: f64, rel_error: f64) -> bool {
//             a == b || (a-b).abs() < abs_error ||

//             if a > b {
//                 ((a-b) / a).abs() > rel_error
//             } else {
//                 ((a-b) / b).abs() > rel_error
//             }
//         }
//         const ABS_ERROR: f64 = 1e-6;
//         const REL_ERROR: f64 = 1e-3;
//         is_equal_float(self.inner, other.inner, ABS_ERROR, REL_ERROR)
//     }
// }

#[allow(dead_code)]
impl Rational {
    fn new(inner: impl Into<BigRational>) -> Rational {
        Rational {
            inner: inner.into()
        }
    }

    fn from_f64(x: f64) -> Option<Rational> {
        match BigRational::from_f64(x) {
            Some(x) => Some(Rational {
                inner: x,
            }),
            None => None
        }
    }

    fn from_u64(x: u64) -> Option<Rational> {
        match BigRational::from_u64(x) {
            Some(x) => Some(Rational {
                inner: x,
            }),
            None => None
        }
    }

    fn from_i64(x: i64) -> Option<Rational> {
        match BigRational::from_i64(x) {
            Some(x) => Some(Rational {
                inner: x,
            }),
            None => None
        }
    }
}

impl Add for Rational {
    type Output = Self;
    fn add(self, other: Self) -> Self::Output {
        Rational::new(self.inner + other.inner) 
    }
}

impl Div for Rational {
    type Output = Self;
    fn div(self, other: Self) -> Self::Output {
        Rational::new(self.inner / other.inner)
    }
}

impl Mul for Rational {
    type Output = Self;
    fn mul(self, other: Self) -> Self::Output {
        Rational::new(self.inner * other.inner)
    }
}

impl Mul<u8> for Rational {
    type Output = Self;
    fn mul(self, other: u8) -> Self::Output {
        let other = BigRational::from_u8(other).unwrap();
        Rational::new(self.inner * other)
    }
}

impl Sub for Rational {
    type Output = Self;
    fn sub(self, other:Self) -> Self::Output {
        Rational::new(self.inner - other.inner)
    }
}

impl From<u8> for Rational {
    fn from(x: u8) -> Self {
        Rational::new(BigRational::new(x.into(), 1.into()))
    }
}

impl SecretType for Rational {
    type Inner = BigRational;

    fn get_inner(&self) -> Self::Inner {
        self.inner.clone()
    }

    fn get_add_identity_elem() -> Self {
        Rational::new(BigRational::from_u8(0).unwrap())
    }

    fn get_mul_identity_elem() -> Self {
        Rational::new(BigRational::from_u8(1).unwrap())
    }
    
    fn deal<R: rand::Rng> (
        threshold: u8,
        secret: &[Self::Inner],
        rng: &mut R,
    ) -> Box<dyn Iterator<Item = Share<Self>>> {
        let mut polys = Vec::with_capacity(secret.len());

        for chunk in secret {
            polys.push(Self::random_polynomial(Rational::new(chunk.clone()), threshold, rng))
        }

        Box::new(Self::get_evaluator(polys))
    }

    fn interpolate(shares: &[Share<Self>]) -> Vec<Self::Inner> {
        (0..shares[0].y.len())
            .map(|s| {
                shares
                    .iter()
                    .map(|s_i| {
                        let product = shares
                                        .iter()
                                        .filter(|s_j| s_j.x != s_i.x)
                                        .map(|s_j|
                                            Self::from(s_j.x) / (Self::from(s_j.x) - Self::from(s_i.x)))
                                        .product::<Self>();
                        product * s_i.y[s].clone()
                    })
                    .sum::<Self>()
                    .get_inner()
            })
        .collect()
    }

    fn random_polynomial<R: rand::Rng>(s: Self, k: u8, rng: &mut R) -> Vec<Self> {
        use rand::distributions::{ Uniform, Distribution };
        let k = k as usize;
        let mut poly = Vec::with_capacity(k);
        let between = Uniform::new_inclusive(1, 255);

        for _ in 1..k {
            let x: u8 = between.sample(rng);
            poly.push(Rational::new(BigRational::from_integer(x.into())));
        }
        poly.push(s);

        poly
    }

    fn get_evaluator(polys: Vec<Vec<Self>>) -> Box<dyn Iterator<Item = Share<Self>>> {
        Box::new((1..=u8::max_value()).map(move |x| Share {
            x,
            y: polys.iter()
                .map(|p| // figure out the result of f_i
                    p.iter().fold(Self::get_add_identity_elem(), |acc, c| acc * x + c.clone())) 
                .collect(),
        }))
    }
    
    fn get_xth_share(ploys: &Vec<Vec<Self>>, x: u8) -> Result<Share<Self>, &'static str> {
        if x == 0 {
            return Err("x cannot be 0");
        }

        Ok(
            Share {
                x,
                y: ploys.iter()
                    .map(|p|
                        p.iter().fold(Self::get_add_identity_elem(), |acc, c| c.clone() + (acc * x))) // figure out the result of f_i
                    .collect(),
            }
        )
    }
}

impl Sum for Rational {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::get_add_identity_elem(), |acc, c| acc + c)
    }
}

impl Product for Rational {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::get_mul_identity_elem(), |acc, c| acc * c)
    }
}

impl From<BigRational> for Rational {
    fn from(inner: BigRational) -> Self {
        Rational {
            inner
        }
}
}

#[cfg(test)]
mod tests {
    use super::Rational;
    use num_rational::BigRational;
    use num_traits::cast::{ FromPrimitive, ToPrimitive };
    use crate::secret_type::SecretType;
    use alloc::vec::Vec;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn get_inner_works() {
        use rand::distributions::{ Distribution, Uniform };
        let mut rng = rand::thread_rng();
        let bwn = Uniform::new_inclusive(1, 255);
        let sample = bwn.sample(&mut rng) as f64;
        assert_eq!(Rational::from_f64(sample).unwrap().get_inner().to_f64().unwrap(), sample);
    }

    mod arithmetic_tests {
        use super::Rational;
        use num_rational::BigRational;
        use num_traits::cast::{ FromPrimitive, ToPrimitive };
        use crate::secret_type::SecretType;

        #[test]
        fn add_id_elem_test() {
            let zero = 0f64;
            assert_eq!(Rational::from_f64(zero).unwrap().get_inner().to_f64().unwrap(), zero);
        }

        #[test]
        fn mul_id_elem_test() {
            let one = 1f64;
            assert_eq!(Rational::from_f64(one).unwrap().get_inner().to_f64().unwrap(), one);
        }

        #[test]
        fn add_works() {
            for i in i8::MIN..i8::MAX {
                for j in i8::MIN..i8::MAX {
                    let i = i as f64;
                    let j = j as f64;
                    let answer = i + j;
                    let result = Rational::from_f64(i).unwrap() + Rational::from_f64(j).unwrap();
                    assert_eq!(result.get_inner().to_f64().unwrap(), answer);
                }
            }
        }

        #[test]
        fn sub_works() {
            for i in i8::MIN..i8::MAX {
                for j in i8::MIN..i8::MAX {
                    let i = i as f64;
                    let j = j as f64;
                    let answer = i - j;
                    let result = Rational::from_f64(i).unwrap() - Rational::from_f64(j).unwrap();
                    assert_eq!(result.get_inner().to_f64().unwrap(), answer);
                }
            }
        }

        #[test]
        fn mul_works() {
            for i in i8::MIN..i8::MAX {
                for j in i8::MIN..i8::MAX {
                    let i = i as f64;
                    let j = j as f64;
                    let answer = i * j;
                    let result = Rational::from_f64(i).unwrap() * Rational::from_f64(j).unwrap();
                    assert_eq!(result.get_inner().to_f64().unwrap(), answer);
                }
            }
        }

        #[test]
        fn div_works() {
            for i in i8::MIN..i8::MAX {
                for j in i8::MIN..i8::MAX {
                    if j == 0 { continue; }

                    let result = Rational::from_i64(i as i64).unwrap() / Rational::from_i64(j as i64).unwrap();
                    let i = i as f64;
                    let j = j as f64;
                    let answer = i / j;

                    // if j == 0f64 {
                    //     let inner = result.get_inner().to_f64().unwrap();
                    //     assert!(inner.is_nan() || inner.is_infinite());
                    // } else {
                        assert_eq!(result.get_inner().to_f64().unwrap(), answer);
                    // }
                }
            }
        }

        // #[test]
        // fn nan_test() {
        //     let nan = f64::NAN;
        //     let nan = Rational::from_f64(nan).unwrap();
        //     assert!(nan.get_inner().to_f64().unwrap().is_nan());

        //     let common = 12f64;
        //     let common = Rational::from_f64(common).unwrap();
        //     assert!(!common.get_inner().to_f64().unwrap().is_nan());
        // }

        // #[test]
        // fn infinite_test() {
        //     let inf = f64::INFINITY;
        //     let inf = Rational::new(BigRational::from_f64(inf).unwrap());
        //     assert!(inf.get_inner().to_f64().unwrap().is_infinite());

        //     let finite = 12f64;
        //     let finite = Rational::new(BigRational::from_f64(finite).unwrap());
        //     assert!(finite.get_inner().to_f64().unwrap().is_finite());
        // }

        /// Generate the input that required by `sum_works` and `product_works`
        fn generate_input() -> Vec<u64> {
            use rand::distributions::{ Distribution, Uniform };
            let mut rng = rand::thread_rng();
            let bwn = Uniform::new_inclusive(1, 25);
            
            const INPUT_LEN: usize = 10; // should not be too big, or the product will overflow
            bwn.sample_iter(&mut rng).take(INPUT_LEN).collect()
        }

        #[test]
        fn sum_works() {
            let input = generate_input();
            let answer = BigRational::from_u64(input.iter().clone().sum::<u64>()).unwrap();
            let answer = Rational::new(answer);
            let result: Rational = input.iter().map(|x| Rational::from_u64(*x).unwrap()).sum();
            assert_eq!(result, answer);
        }

        #[test]
        fn product_works() {
            let input = generate_input();
            let answer = input.iter().map(|x| *x).product::<u64>();
            let answer = BigRational::from_u64(answer).unwrap();
            let answer = Rational::new(answer);
            let result: Rational = input.iter().map(|x| Rational::from_u64(*x).unwrap()).product();
            assert!((answer.get_inner().to_f64().unwrap() - result.get_inner().to_f64().unwrap()).abs() <= 1e-7);
        }
    }

    #[test]
    fn random_polynomial_works() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
        let secret = Rational::from_u64(12).unwrap();
        let threshold = 3;
        let poly = Rational::random_polynomial(secret.clone(), threshold, &mut rng);
        assert_eq!(poly.len(), threshold as usize);
        assert_eq!(poly[poly.len()-1], secret);
    }

    #[test]
    fn evaluator_works() {
        let iter = Rational::get_evaluator(
            vec![vec![Rational::from_u64(3).unwrap(), Rational::from_u64(2).unwrap(), Rational::from_u64(5).unwrap()]]
        );
        let values: Vec<_> = iter.take(2).map(|s| (s.x, s.y)).collect();
        assert_eq!(
            values,
            vec![(1, vec![Rational::from_u64(10).unwrap()]), (2, vec![Rational::from_u64(21).unwrap()])]
        );
    }

    #[test]
    fn interpolate_works() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
        let secret = 185f64;
        let threshold = 10;
        let poly = Rational::random_polynomial(Rational::new(BigRational::from_f64(secret).unwrap()), threshold, &mut rng);
        let iter = Rational::get_evaluator(vec![poly]);
        let shares: Vec<_> = iter.take(threshold as usize).collect();
        let root = Rational::interpolate(&shares);
        assert!((root[0].to_f64().unwrap() - secret).abs() <= 1e-7);
    }
}
