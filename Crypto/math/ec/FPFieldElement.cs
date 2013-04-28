using System;
using System.Diagnostics;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Utilities;
using Random = Org.BouncyCastle.Bcpg.Random;

namespace Org.BouncyCastle.Math.EC
{
    public class FPFieldElement : ECFieldElement
    {
        private readonly IBigInteger _q, _x;

        /// <summary>
        /// Initializes a new instance of the <see cref="FPFieldElement"/> class.
        /// </summary>
        /// <param name="q">The q.</param>
        /// <param name="x">The x.</param>
        /// <exception cref="System.ArgumentException">x value too large in field element</exception>
        public FPFieldElement(IBigInteger q, IBigInteger x)
        {
            if (x.CompareTo(q) >= 0)
                throw new ArgumentException("x value too large in field element");

            _q = q;
            _x = x;
        }

        public override IBigInteger ToBigInteger()
        {
            return _x;
        }

        /// <summary>
        /// Gets the name of the field.
        /// </summary>
        /// <value>
        /// The name of the field.
        /// </value>
        public override string FieldName
        {
            get { return "Fp"; }
        }

        /// <summary>
        /// Gets the size of the field.
        /// </summary>
        /// <value>
        /// The size of the field.
        /// </value>
        public override int FieldSize
        {
            get { return _q.BitLength; }
        }

        /// <summary>
        /// Gets the Q.
        /// </summary>
        /// <value>
        /// The Q.
        /// </value>
        public IBigInteger Q
        {
            get { return _q; }
        }

        public override ECFieldElement Add(ECFieldElement b)
        {
            return new FPFieldElement(_q, _x.Add(b.ToBigInteger()).Mod(_q));
        }

        public override ECFieldElement Subtract(ECFieldElement b)
        {
            return new FPFieldElement(_q, _x.Subtract(b.ToBigInteger()).Mod(_q));
        }

        public override ECFieldElement Multiply(ECFieldElement b)
        {
            return new FPFieldElement(_q, _x.Multiply(b.ToBigInteger()).Mod(_q));
        }

        public override ECFieldElement Divide(ECFieldElement b)
        {
            return new FPFieldElement(_q, _x.Multiply(b.ToBigInteger().ModInverse(_q)).Mod(_q));
        }

        public override ECFieldElement Negate()
        {
            return new FPFieldElement(_q, _x.Negate().Mod(_q));
        }

        public override ECFieldElement Square()
        {
            return new FPFieldElement(_q, _x.Multiply(_x).Mod(_q));
        }

        public override ECFieldElement Invert()
        {
            return new FPFieldElement(_q, _x.ModInverse(_q));
        }

        /// <summary>
        /// D.1.4 91
        /// return a sqrt root - the routine verifies that the calculation
        /// returns the right value - if none exists it returns null.
        /// </summary>
        /// <returns></returns>
        public override ECFieldElement Sqrt()
        {
            if (!_q.TestBit(0))
                throw Platform.CreateNotImplementedException("even value of q");

            // p mod 4 == 3
            if (_q.TestBit(1))
            {
                // TODO Can this be optimised (inline the Square?)
                // z = g^(u+1) + p, p = 4u + 3
                var z = new FPFieldElement(_q, _x.ModPow(_q.ShiftRight(2).Add(BigInteger.One), _q));

                return z.Square().Equals(this) ? z : null;
            }

            // p mod 4 == 1
            var qMinusOne = _q.Subtract(BigInteger.One);

            var legendreExponent = qMinusOne.ShiftRight(1);
            if (!(_x.ModPow(legendreExponent, _q).Equals(BigInteger.One)))
                return null;

            var u = qMinusOne.ShiftRight(2);
            var k = u.ShiftLeft(1).Add(BigInteger.One);

            var Q = _x;
            var fourQ = Q.ShiftLeft(2).Mod(_q);

            IBigInteger U;
            IBigInteger V;
            do
            {
                IRandom rand = new Random();
                IBigInteger P;
                do
                {
                    P = new BigInteger(_q.BitLength, rand);
                }
                while (P.CompareTo(_q) >= 0
                       || !(P.Multiply(P).Subtract(fourQ).ModPow(legendreExponent, _q).Equals(qMinusOne)));

                var result = FastLucasSequence(_q, P, Q, k);
                U = result[0];
                V = result[1];

                if (!V.Multiply(V).Mod(_q).Equals(fourQ))
                    continue;

                // Integer division by 2, mod q
                if (V.TestBit(0))
                {
                    V = V.Add(_q);
                }

                V = V.ShiftRight(1);

                Debug.Assert(V.Multiply(V).Mod(_q).Equals(_x));

                return new FPFieldElement(_q, V);
            }
            while (U.Equals(BigInteger.One) || U.Equals(qMinusOne));

            return null;
        }

        private static IBigInteger[] FastLucasSequence(IBigInteger p, IBigInteger P, IBigInteger Q, IBigInteger k)
        {
            // TODO Research and apply "common-multiplicand multiplication here"

            var n = k.BitLength;
            var s = k.GetLowestSetBit();

            Debug.Assert(k.TestBit(s));

            var uh = BigInteger.One;
            var vl = BigInteger.Two;
            var vh = P;
            var ql = BigInteger.One;
            var qh = BigInteger.One;

            for (var j = n - 1; j >= s + 1; --j)
            {
                ql = ql.Multiply(qh).Mod(p);

                if (k.TestBit(j))
                {
                    qh = ql.Multiply(Q).Mod(p);
                    uh = uh.Multiply(vh).Mod(p);
                    vl = vh.Multiply(vl).Subtract(P.Multiply(ql)).Mod(p);
                    vh = vh.Multiply(vh).Subtract(qh.ShiftLeft(1)).Mod(p);
                }
                else
                {
                    qh = ql;
                    uh = uh.Multiply(vl).Subtract(ql).Mod(p);
                    vh = vh.Multiply(vl).Subtract(P.Multiply(ql)).Mod(p);
                    vl = vl.Multiply(vl).Subtract(ql.ShiftLeft(1)).Mod(p);
                }
            }

            ql = ql.Multiply(qh).Mod(p);
            qh = ql.Multiply(Q).Mod(p);
            uh = uh.Multiply(vl).Subtract(ql).Mod(p);
            vl = vh.Multiply(vl).Subtract(P.Multiply(ql)).Mod(p);
            ql = ql.Multiply(qh).Mod(p);

            for (var j = 1; j <= s; ++j)
            {
                uh = uh.Multiply(vl).Mod(p);
                vl = vl.Multiply(vl).Subtract(ql.ShiftLeft(1)).Mod(p);
                ql = ql.Multiply(ql).Mod(p);
            }

            return new[] { uh, vl };
        }

        //		private static BigInteger[] verifyLucasSequence(
        //			BigInteger	p,
        //			BigInteger	P,
        //			BigInteger	Q,
        //			BigInteger	k)
        //		{
        //			BigInteger[] actual = fastLucasSequence(p, P, Q, k);
        //			BigInteger[] plus1 = fastLucasSequence(p, P, Q, k.Add(BigInteger.One));
        //			BigInteger[] plus2 = fastLucasSequence(p, P, Q, k.Add(BigInteger.Two));
        //
        //			BigInteger[] check = stepLucasSequence(p, P, Q, actual, plus1);
        //
        //			Debug.Assert(check[0].Equals(plus2[0]));
        //			Debug.Assert(check[1].Equals(plus2[1]));
        //
        //			return actual;
        //		}
        //
        //		private static BigInteger[] stepLucasSequence(
        //			BigInteger		p,
        //			BigInteger		P,
        //			BigInteger		Q,
        //			BigInteger[]	backTwo,
        //			BigInteger[]	backOne)
        //		{
        //			return new BigInteger[]
        //			{
        //				P.Multiply(backOne[0]).Subtract(Q.Multiply(backTwo[0])).Mod(p),
        //				P.Multiply(backOne[1]).Subtract(Q.Multiply(backTwo[1])).Mod(p)
        //			};
        //		}

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as FPFieldElement;
            return other != null && Equals(other);
        }

        protected bool Equals(FPFieldElement other)
        {
            return _q.Equals(other._q) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return _q.GetHashCode() ^ base.GetHashCode();
        }
    }
}