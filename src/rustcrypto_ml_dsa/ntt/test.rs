use super::*;
use hybrid_array::{
    Array,
    typenum::{U2, U3},
};

use super::super::algebra::*;

// Multiplication in R_q, modulo X^256 + 1
fn poly_mul(lhs: &Polynomial, rhs: &Polynomial) -> Polynomial {
    let mut out = Polynomial::default();
    for (i, x) in lhs.0.iter().enumerate() {
        for (j, y) in rhs.0.iter().enumerate() {
            let (sign, index) = if i + j < 256 {
                (Elem::new(1), i + j)
            } else {
                (Elem::new(BaseField::Q - 1), i + j - 256)
            };

            out.0[index] = out.0[index] + (sign * *x * *y);
        }
    }
    out
}

// A polynomial with only a scalar component, to make simple test cases
fn const_ntt(x: Int) -> NttPolynomial {
    let mut p = Polynomial::default();
    p.0[0] = Elem::new(x);
    p.ntt()
}

#[test]
fn ntt() {
    let f = Polynomial::new(Array::from_fn(|i| Elem::new(Int::try_from(i).unwrap())));
    let g = Polynomial::new(Array::from_fn(|i| Elem::new(Int::try_from(2 * i).unwrap())));
    let f_hat = f.ntt();
    let g_hat = g.ntt();

    // Verify that NTT and NTT^-1 are actually inverses
    let f_unhat = f_hat.ntt_inverse();
    assert_eq!(f, f_unhat);

    // Verify that NTT is a homomorphism with regard to addition
    let sum = &f + &g;
    let transformed_sum = &f_hat + &g_hat;
    let recovered_sum = transformed_sum.ntt_inverse();
    assert_eq!(sum, recovered_sum);

    // Verify that NTT is a homomorphism with regard to multiplication
    let product = poly_mul(&f, &g);
    let transformed_product = &f_hat * &g_hat;
    let recovered_product = transformed_product.ntt_inverse();
    assert_eq!(product, recovered_product);
}

#[test]
fn ntt_vector() {
    // Verify vector addition
    let v1: NttVector<U3> = NttVector::new(Array([const_ntt(1), const_ntt(1), const_ntt(1)]));
    let v2: NttVector<U3> = NttVector::new(Array([const_ntt(2), const_ntt(2), const_ntt(2)]));
    let v3: NttVector<U3> = NttVector::new(Array([const_ntt(3), const_ntt(3), const_ntt(3)]));
    assert_eq!((&v1 + &v2), v3);

    // Verify dot product
    assert_eq!((&v1 * &v2), const_ntt(6));
    assert_eq!((&v1 * &v3), const_ntt(9));
    assert_eq!((&v2 * &v3), const_ntt(18));
}

#[test]
fn ntt_matrix() {
    // Verify matrix multiplication by a vector
    let a: NttMatrix<U3, U2> = NttMatrix::new(Array([
        NttVector::new(Array([const_ntt(1), const_ntt(2)])),
        NttVector::new(Array([const_ntt(3), const_ntt(4)])),
        NttVector::new(Array([const_ntt(5), const_ntt(6)])),
    ]));
    let v_in: NttVector<U2> = NttVector::new(Array([const_ntt(1), const_ntt(2)]));
    let v_out: NttVector<U3> = NttVector::new(Array([const_ntt(5), const_ntt(11), const_ntt(17)]));
    assert_eq!(&a * &v_in, v_out);
}
