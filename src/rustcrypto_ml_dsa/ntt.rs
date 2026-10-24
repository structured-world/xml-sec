use super::algebra::{BaseField, Elem, NttPolynomial, NttVector, Polynomial, Vector};
use module_lattice::{ArraySize, Field, MultiplyNtt};

// Since the powers of zeta used in the NTT and MultiplyNTTs are fixed, we use pre-computed tables
// to avoid the need to compute the exponentiations at runtime.
//
//   ZETA_POW_BITREV[i] = zeta^{BitRev_8(i)}
//
// Note that the const environment here imposes some annoying conditions.  Because operator
// overloading can't be const, we have to do all the reductions here manually.  Because `for` loops
// are forbidden in `const` functions, we do them manually with `while` loops.
//
// The values computed here match those provided in Appendix B of FIPS 204.
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const ZETA_POW_BITREV: [Elem; 256] = {
    const ZETA: u64 = 1753;
    const fn bitrev8(x: usize) -> usize {
        x.reverse_bits() >> (usize::BITS - 8)
    }

    // Compute the powers of zeta
    let mut pow = [Elem::new(0); 256];
    let mut i = 0;
    let mut curr = 1u64;
    while i < 256 {
        let bytes = curr.to_le_bytes();
        pow[i] = Elem::new(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        i += 1;
        curr = (curr * ZETA) % BaseField::QL;
    }

    // Reorder the powers according to bitrev8
    // Note that entry 0 is left as zero, in order to match the `zetas` array in the
    // specification.
    let mut pow_bitrev = [Elem::new(0); 256];
    let mut i = 1;
    while i < 256 {
        pow_bitrev[i] = pow[bitrev8(i)];
        i += 1;
    }
    pow_bitrev
};

pub(crate) trait Ntt {
    type Output;
    fn ntt(&self) -> Self::Output;
}

// Expand each layer with literal loop bounds, avoiding runtime step division
// and preserving call-site expansion without an inlining attribute.
macro_rules! ntt_layer {
    ($w:expr, $m:expr, $len:literal, $iterations:literal) => {{
        let w = &mut $w;
        let m = &mut $m;
        for i in 0..$iterations {
            let start = i * 2 * $len;
            *m += 1;
            let z = ZETA_POW_BITREV[*m];
            for j in start..(start + $len) {
                let t = z * w[j + $len];
                w[j + $len] = w[j] - t;
                w[j] = w[j] + t;
            }
        }
    }};
}

impl Ntt for Polynomial {
    type Output = NttPolynomial;

    // Algorithm 41 NTT
    //
    // This implementation expands layers at each call site to ensure all loop
    // bounds are compile-time constants, avoiding potential UDIV instructions.
    fn ntt(&self) -> Self::Output {
        let mut w: [Elem; 256] = self.0.clone().into();
        let mut m = 0;

        ntt_layer!(w, m, 128, 1);
        ntt_layer!(w, m, 64, 2);
        ntt_layer!(w, m, 32, 4);
        ntt_layer!(w, m, 16, 8);
        ntt_layer!(w, m, 8, 16);
        ntt_layer!(w, m, 4, 32);
        ntt_layer!(w, m, 2, 64);
        ntt_layer!(w, m, 1, 128);

        NttPolynomial::new(w.into())
    }
}

impl<K: ArraySize> Ntt for Vector<K> {
    type Output = NttVector<K>;

    fn ntt(&self) -> Self::Output {
        NttVector::new(self.0.iter().map(Polynomial::ntt).collect())
    }
}

#[allow(clippy::module_name_repetitions)]
pub(crate) trait NttInverse {
    type Output;
    fn ntt_inverse(&self) -> Self::Output;
}

// The inverse uses the same call-site expansion and fixed layer bounds.
macro_rules! ntt_inverse_layer {
    ($w:expr, $m:expr, $len:literal, $iterations:literal) => {{
        let w = &mut $w;
        let m = &mut $m;
        for i in 0..$iterations {
            let start = i * 2 * $len;
            *m -= 1;
            let z = -ZETA_POW_BITREV[*m];
            for j in start..(start + $len) {
                let t = w[j];
                w[j] = t + w[j + $len];
                w[j + $len] = z * (t - w[j + $len]);
            }
        }
    }};
}

impl NttInverse for NttPolynomial {
    type Output = Polynomial;

    // Algorithm 42 NTT^{−1}
    //
    // This implementation expands layers at each call site to ensure all loop
    // bounds are compile-time constants, avoiding potential UDIV instructions.
    fn ntt_inverse(&self) -> Self::Output {
        const INVERSE_256: Elem = Elem::new(8_347_681);

        let mut w: [Elem; 256] = self.0.clone().into();
        let mut m = 256;

        ntt_inverse_layer!(w, m, 1, 128);
        ntt_inverse_layer!(w, m, 2, 64);
        ntt_inverse_layer!(w, m, 4, 32);
        ntt_inverse_layer!(w, m, 8, 16);
        ntt_inverse_layer!(w, m, 16, 8);
        ntt_inverse_layer!(w, m, 32, 4);
        ntt_inverse_layer!(w, m, 64, 2);
        ntt_inverse_layer!(w, m, 128, 1);

        INVERSE_256 * &Polynomial::new(w.into())
    }
}

impl<K: ArraySize> NttInverse for NttVector<K> {
    type Output = Vector<K>;

    fn ntt_inverse(&self) -> Self::Output {
        Vector::new(self.0.iter().map(NttPolynomial::ntt_inverse).collect())
    }
}

impl MultiplyNtt for BaseField {
    // Algorithm 45 MultiplyNTT
    fn multiply_ntt(lhs: &NttPolynomial, rhs: &NttPolynomial) -> NttPolynomial {
        NttPolynomial::new(
            lhs.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x * y)
                .collect(),
        )
    }
}

#[cfg(test)]
mod test;
