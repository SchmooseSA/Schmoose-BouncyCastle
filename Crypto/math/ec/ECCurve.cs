using System;

using Org.BouncyCastle.Math.EC.Abc;
using Random = Org.BouncyCastle.Bcpg.Random;

namespace Org.BouncyCastle.Math.EC
{
    /// <remarks>Base class for an elliptic curve.</remarks>
    public abstract class ECCurve
    {
        public abstract int FieldSize { get; }
        public abstract ECFieldElement FromBigInteger(IBigInteger x);
        public abstract ECPoint CreatePoint(IBigInteger x1, IBigInteger y1, bool withCompression);
        public abstract ECPoint DecodePoint(byte[] encoded);
        public abstract ECPoint Infinity { get; }

        public ECFieldElement A { get; protected set; }

        public ECFieldElement B { get; protected set; }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as ECCurve;
            return other != null && Equals(other);
        }

        protected bool Equals(ECCurve other)
        {
            return this.A.Equals(other.A) && this.B.Equals(other.B);
        }

        public override int GetHashCode()
        {
            return this.A.GetHashCode() ^ this.B.GetHashCode();
        }
    }

    public abstract class ECCurveBase : ECCurve
    {
        protected internal ECCurveBase()
        {
        }

        protected internal abstract ECPoint DecompressPoint(int yTilde, IBigInteger x1);

        /**
         * Decode a point on this curve from its ASN.1 encoding. The different
         * encodings are taken account of, including point compression for
         * <code>F<sub>p</sub></code> (X9.62 s 4.2.1 pg 17).
         * @return The decoded point.
         */
        public override ECPoint DecodePoint(byte[] encoded)
        {
            ECPoint p;
            var expectedLength = (FieldSize + 7) / 8;

            switch (encoded[0])
            {
                case 0x00: // infinity
                    {
                        if (encoded.Length != 1)
                            throw new ArgumentException(@"Incorrect length for infinity encoding", "encoded");

                        p = Infinity;
                        break;
                    }

                case 0x02: // compressed
                case 0x03: // compressed
                    {
                        if (encoded.Length != (expectedLength + 1))
                            throw new ArgumentException(@"Incorrect length for compressed encoding", "encoded");

                        var yTilde = encoded[0] & 1;
                        IBigInteger x1 = new BigInteger(1, encoded, 1, encoded.Length - 1);

                        p = DecompressPoint(yTilde, x1);
                        break;
                    }

                case 0x04: // uncompressed
                case 0x06: // hybrid
                case 0x07: // hybrid
                    {
                        if (encoded.Length != (2 * expectedLength + 1))
                            throw new ArgumentException(@"Incorrect length for uncompressed/hybrid encoding", "encoded");

                        IBigInteger x1 = new BigInteger(1, encoded, 1, expectedLength);
                        IBigInteger y1 = new BigInteger(1, encoded, 1 + expectedLength, expectedLength);

                        p = CreatePoint(x1, y1, false);
                        break;
                    }

                default:
                    throw new FormatException("Invalid point encoding " + encoded[0]);
            }

            return p;
        }
    }

    /**
     * Elliptic curve over Fp
     */
    public class FPCurve : ECCurveBase
    {
        private readonly IBigInteger _q;
        private readonly FPPoint _infinity;

        public FPCurve(IBigInteger q, IBigInteger a, IBigInteger b)
        {
            _q = q;

            this.A = FromBigInteger(a);
            this.B = FromBigInteger(b);
            _infinity = new FPPoint(this, null, null);
        }

        public IBigInteger Q
        {
            get { return _q; }
        }

        public override ECPoint Infinity
        {
            get { return _infinity; }
        }

        public override int FieldSize
        {
            get { return _q.BitLength; }
        }

        public override ECFieldElement FromBigInteger(IBigInteger x)
        {
            return new FPFieldElement(_q, x);
        }

        public override ECPoint CreatePoint(IBigInteger x1, IBigInteger y1, bool withCompression)
        {
            // TODO Validation of X1, Y1?
            return new FPPoint(this, FromBigInteger(x1), FromBigInteger(y1), withCompression);
        }

        protected internal override ECPoint DecompressPoint(int yTilde, IBigInteger x1)
        {
            var x = FromBigInteger(x1);
            var alpha = x.Multiply(x.Square().Add(this.A)).Add(this.B);
            var beta = alpha.Sqrt();

            //
            // if we can't find a sqrt we haven't got a point on the
            // curve - run!
            //
            if (beta == null)
                throw new ArithmeticException("Invalid point compression");

            var betaValue = beta.ToBigInteger();
            var bit0 = betaValue.TestBit(0) ? 1 : 0;

            if (bit0 != yTilde)
            {
                // Use the other root
                beta = FromBigInteger(_q.Subtract(betaValue));
            }

            return new FPPoint(this, x, beta, true);
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as FPCurve;
            return other != null && Equals(other);
        }

        protected bool Equals(FPCurve other)
        {
            return base.Equals(other) && _q.Equals(other._q);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode() ^ _q.GetHashCode();
        }
    }

    /**
     * Elliptic curves over F2m. The Weierstrass equation is given by
     * <code>y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b</code>.
     */
    public class F2MCurve : ECCurveBase
    {
        /**
         * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
         */
        private readonly int _m;

        /**
         * TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction polynomial
         * <code>f(z)</code>.<br/>
         * PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br/>
         */
        private readonly int _k1;

        /**
         * TPB: Always set to <code>0</code><br/>
         * PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br/>
         */
        private readonly int _k2;

        /**
         * TPB: Always set to <code>0</code><br/>
         * PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br/>
         */
        private readonly int _k3;

        /**
         * The order of the base point of the curve.
         */
        private readonly IBigInteger _n;

        /**
         * The cofactor of the curve.
         */
        private readonly IBigInteger _h;

        /**
         * The point at infinity on this curve.
         */
        private readonly F2MPoint _infinity;

        /**
         * The parameter <code>&#956;</code> of the elliptic curve if this is
         * a Koblitz curve.
         */
        private sbyte _mu;

        /**
         * The auxiliary values <code>s<sub>0</sub></code> and
         * <code>s<sub>1</sub></code> used for partial modular reduction for
         * Koblitz curves.
         */
        private volatile IBigInteger[] _si;

        /**
         * Constructor for Trinomial Polynomial Basis (TPB).
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction
         * polynomial <code>f(z)</code>.
         * @param a The coefficient <code>a</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param b The coefficient <code>b</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         */
        public F2MCurve(
            int m,
            int k,
            IBigInteger a,
            IBigInteger b)
            : this(m, k, 0, 0, a, b, null, null)
        {
        }

        /**
         * Constructor for Trinomial Polynomial Basis (TPB).
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction
         * polynomial <code>f(z)</code>.
         * @param a The coefficient <code>a</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param b The coefficient <code>b</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param n The order of the main subgroup of the elliptic curve.
         * @param h The cofactor of the elliptic curve, i.e.
         * <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>.
         */
        public F2MCurve(
            int m,
            int k,
            IBigInteger a,
            IBigInteger b,
            IBigInteger n,
            IBigInteger h)
            : this(m, k, 0, 0, a, b, n, h)
        {
        }

        /**
         * Constructor for Pentanomial Polynomial Basis (PPB).
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param a The coefficient <code>a</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param b The coefficient <code>b</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         */
        public F2MCurve(
            int m,
            int k1,
            int k2,
            int k3,
            IBigInteger a,
            IBigInteger b)
            : this(m, k1, k2, k3, a, b, null, null)
        {
        }

        /**
         * Constructor for Pentanomial Polynomial Basis (PPB).
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param a The coefficient <code>a</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param b The coefficient <code>b</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param n The order of the main subgroup of the elliptic curve.
         * @param h The cofactor of the elliptic curve, i.e.
         * <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>.
         */
        public F2MCurve(
            int m,
            int k1,
            int k2,
            int k3,
            IBigInteger a,
            IBigInteger b,
            IBigInteger n,
            IBigInteger h)
        {
            this._m = m;
            this._k1 = k1;
            this._k2 = k2;
            this._k3 = k3;
            this._n = n;
            this._h = h;
            this._infinity = new F2MPoint(this, null, null);

            if (k1 == 0)
                throw new ArgumentException("k1 must be > 0");

            if (k2 == 0)
            {
                if (k3 != 0)
                    throw new ArgumentException("k3 must be 0 if k2 == 0");
            }
            else
            {
                if (k2 <= k1)
                    throw new ArgumentException("k2 must be > k1");

                if (k3 <= k2)
                    throw new ArgumentException("k3 must be > k2");
            }

            this.A = FromBigInteger(a);
            this.B = FromBigInteger(b);
        }

        public override ECPoint Infinity
        {
            get { return _infinity; }
        }

        public override int FieldSize
        {
            get { return _m; }
        }

        public override ECFieldElement FromBigInteger(IBigInteger x)
        {
            return new F2MFieldElement(this._m, this._k1, this._k2, this._k3, x);
        }

        /**
         * Returns true if this is a Koblitz curve (ABC curve).
         * @return true if this is a Koblitz curve (ABC curve), false otherwise
         */
        public bool IsKoblitz
        {
            get
            {
                return _n != null && _h != null
                    && (A.ToBigInteger().Equals(BigInteger.Zero)
                        || A.ToBigInteger().Equals(BigInteger.One))
                    && B.ToBigInteger().Equals(BigInteger.One);
            }
        }

        /**
         * Returns the parameter <code>&#956;</code> of the elliptic curve.
         * @return <code>&#956;</code> of the elliptic curve.
         * @throws ArgumentException if the given ECCurve is not a
         * Koblitz curve.
         */
        internal sbyte GetMu()
        {
            if (_mu == 0)
            {
                lock (this)
                {
                    if (_mu == 0)
                    {
                        _mu = Tnaf.GetMu(this);
                    }
                }
            }

            return _mu;
        }

        /**
         * @return the auxiliary values <code>s<sub>0</sub></code> and
         * <code>s<sub>1</sub></code> used for partial modular reduction for
         * Koblitz curves.
         */
        internal IBigInteger[] GetSi()
        {
            if (_si == null)
            {
                lock (this)
                {
                    if (_si == null)
                    {
                        _si = Tnaf.GetSi(this);
                    }
                }
            }
            return _si;
        }

        public override ECPoint CreatePoint(
            IBigInteger x1,
            IBigInteger y1,
            bool withCompression)
        {
            // TODO Validation of X1, Y1?
            return new F2MPoint(
                this,
                FromBigInteger(x1),
                FromBigInteger(y1),
                withCompression);
        }

        protected internal override ECPoint DecompressPoint(int yTilde, IBigInteger x1)
        {
            var xp = FromBigInteger(x1);
            ECFieldElement yp;
            if (xp.ToBigInteger().SignValue == 0)
            {
                yp = this.B;
                for (var i = 0; i < _m - 1; i++)
                {
                    yp = yp.Square();
                }
            }
            else
            {
                var beta = xp.Add(this.A).Add(this.B.Multiply(xp.Square().Invert()));
                var z = SolveQuadradicEquation(beta);

                if (z == null)
                    throw new ArithmeticException("Invalid point compression");

                var zBit = z.ToBigInteger().TestBit(0) ? 1 : 0;
                if (zBit != yTilde)
                {
                    z = z.Add(FromBigInteger(BigInteger.One));
                }

                yp = xp.Multiply(z);
            }

            return new F2MPoint(this, xp, yp, true);
        }

        /**
         * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
         * D.1.6) The other solution is <code>z + 1</code>.
         *
         * @param beta
         *            The value to solve the qradratic equation for.
         * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
         *         <code>null</code> if no solution exists.
         */
        private ECFieldElement SolveQuadradicEquation(ECFieldElement beta)
        {
            if (beta.ToBigInteger().SignValue == 0)
            {
                return FromBigInteger(BigInteger.Zero);
            }

            ECFieldElement z = null;
            var gamma = FromBigInteger(BigInteger.Zero);

            while (gamma.ToBigInteger().SignValue == 0)
            {
                var t = FromBigInteger(new BigInteger(_m, new Random()));
                z = FromBigInteger(BigInteger.Zero);

                var w = beta;
                for (var i = 1; i <= _m - 1; i++)
                {
                    var w2 = w.Square();
                    z = z.Square().Add(w2.Multiply(t));
                    w = w2.Add(beta);
                }
                if (w.ToBigInteger().SignValue != 0)
                {
                    return null;
                }
                gamma = z.Square().Add(z);
            }
            return z;
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as F2MCurve;
            return other != null && Equals(other);
        }

        protected bool Equals(F2MCurve other)
        {
            return _m == other._m
                && _k1 == other._k1
                && _k2 == other._k2
                && _k3 == other._k3
                && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode() ^ _m ^ _k1 ^ _k2 ^ _k3;
        }

        public int M
        {
            get { return _m; }
        }

        /**
         * Return true if curve uses a Trinomial basis.
         *
         * @return true if curve Trinomial, false otherwise.
         */
        public bool IsTrinomial()
        {
            return _k2 == 0 && _k3 == 0;
        }

        public int K1
        {
            get { return _k1; }
        }

        public int K2
        {
            get { return _k2; }
        }

        public int K3
        {
            get { return _k3; }
        }

        public IBigInteger N
        {
            get { return _n; }
        }

        public IBigInteger H
        {
            get { return _h; }
        }
    }
}
