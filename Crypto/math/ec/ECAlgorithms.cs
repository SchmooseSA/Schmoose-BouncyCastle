using System;

namespace Org.BouncyCastle.Math.EC
{
    public class ECAlgorithms
    {
        public static ECPoint SumOfTwoMultiplies(ECPoint p, IBigInteger a, ECPoint q, IBigInteger b)
        {
            var c = p.Curve;
            if (!c.Equals(q.Curve))
                throw new ArgumentException("P and Q must be on same curve");

            // Point multiplication for Koblitz curves (using WTNAF) beats Shamir's trick
            var f2MCurve = c as F2MCurve;
            if (f2MCurve != null)
            {
                if (f2MCurve.IsKoblitz)
                {
                    return p.Multiply(a).Add(q.Multiply(b));
                }
            }

            return ImplShamirsTrick(p, a, q, b);
        }

        /*
        * "Shamir's Trick", originally due to E. G. Straus
        * (Addition chains of vectors. American Mathematical Monthly,
        * 71(7):806-808, Aug./Sept. 1964)
        *  
        * Input: The points P, Q, scalar k = (km?, ... , k1, k0)
        * and scalar l = (lm?, ... , l1, l0).
        * Output: R = k * P + l * Q.
        * 1: Z <- P + Q
        * 2: R <- O
        * 3: for i from m-1 down to 0 do
        * 4:        R <- R + R        {point doubling}
        * 5:        if (ki = 1) and (li = 0) then R <- R + P end if
        * 6:        if (ki = 0) and (li = 1) then R <- R + Q end if
        * 7:        if (ki = 1) and (li = 1) then R <- R + Z end if
        * 8: end for
        * 9: return R
        */
        public static ECPoint ShamirsTrick(ECPoint p, BigInteger k, ECPoint q, BigInteger l)
        {
            if (!p.Curve.Equals(q.Curve))
                throw new ArgumentException("P and Q must be on same curve");

            return ImplShamirsTrick(p, k, q, l);
        }

        private static ECPoint ImplShamirsTrick(ECPoint p, IBigInteger k, ECPoint q, IBigInteger l)
        {
            var m = System.Math.Max(k.BitLength, l.BitLength);
            var z = p.Add(q);
            var r = p.Curve.Infinity;

            for (var i = m - 1; i >= 0; --i)
            {
                r = r.Twice();

                if (k.TestBit(i))
                {
                    r = r.Add(l.TestBit(i) ? z : p);
                }
                else
                {
                    if (l.TestBit(i))
                    {
                        r = r.Add(q);
                    }
                }
            }

            return r;
        }
    }
}
