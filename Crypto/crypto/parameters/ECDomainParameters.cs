using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECDomainParameters
    {
        private readonly ECCurve _curve;
        private readonly byte[] _seed;
        private readonly ECPoint _g;
        private readonly IBigInteger _n;
        private readonly IBigInteger _h;

        public ECDomainParameters(ECCurve curve, ECPoint g, IBigInteger n)
            : this(curve, g, n, BigInteger.One)
        {
        }

        public ECDomainParameters(ECCurve curve, ECPoint g, IBigInteger n, IBigInteger h)
            : this(curve, g, n, h, null)
        {
        }

        public ECDomainParameters(ECCurve curve, ECPoint g, IBigInteger n, IBigInteger h, byte[] seed)
        {
            if (curve == null)
                throw new ArgumentNullException("curve");
            if (g == null)
                throw new ArgumentNullException("g");
            if (n == null)
                throw new ArgumentNullException("n");
            if (h == null)
                throw new ArgumentNullException("h");

            _curve = curve;
            _g = g;
            _n = n;
            _h = h;
            _seed = Arrays.Clone(seed);
        }

        public ECCurve Curve
        {
            get { return _curve; }
        }

        public ECPoint G
        {
            get { return _g; }
        }

        public IBigInteger N
        {
            get { return _n; }
        }

        public IBigInteger H
        {
            get { return _h; }
        }

        public byte[] GetSeed()
        {
            return Arrays.Clone(_seed);
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as ECDomainParameters;
            return other != null && Equals(other);
        }

        protected bool Equals(ECDomainParameters other)
        {
            return _curve.Equals(other.Curve)
                && _g.Equals(other.G)
                && _n.Equals(other.N)
                && _h.Equals(other.H)
                && Arrays.AreEqual(_seed, other._seed);
        }

        public override int GetHashCode()
        {
            return _curve.GetHashCode()
                ^ _g.GetHashCode()
                ^ _n.GetHashCode()
                ^ _h.GetHashCode()
                ^ Arrays.GetHashCode(_seed);
        }
    }
}
