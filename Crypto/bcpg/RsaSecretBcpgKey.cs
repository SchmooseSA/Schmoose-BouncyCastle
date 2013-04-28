using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Base class for an RSA secret (or priate) key.</remarks>
    public class RsaSecretBcpgKey : BcpgObject, IBcpgKey
    {
        private readonly MPInteger _d, _p, _q, _u;
        private readonly IBigInteger _expP, _expQ, _crt;

        public RsaSecretBcpgKey(BcpgInputStream bcpgIn)
        {
            _d = new MPInteger(bcpgIn);
            _p = new MPInteger(bcpgIn);
            _q = new MPInteger(bcpgIn);
            _u = new MPInteger(bcpgIn);

            _expP = _d.Value.Remainder(_p.Value.Subtract(BigInteger.One));
            _expQ = _d.Value.Remainder(_q.Value.Subtract(BigInteger.One));
            _crt = _q.Value.ModInverse(_p.Value);
        }

        public RsaSecretBcpgKey(IBigInteger d, IBigInteger p, IBigInteger q)
        {
            // PGP requires (p < q)
            var cmp = p.CompareTo(q);
            if (cmp >= 0)
            {
                if (cmp == 0)
                    throw new ArgumentException("p and q cannot be equal");

                var tmp = p;
                p = q;
                q = tmp;
            }

            _d = new MPInteger(d);
            _p = new MPInteger(p);
            _q = new MPInteger(q);
            _u = new MPInteger(p.ModInverse(q));

            _expP = d.Remainder(p.Subtract(BigInteger.One));
            _expQ = d.Remainder(q.Subtract(BigInteger.One));
            _crt = q.ModInverse(p);
        }

        public IBigInteger Modulus
        {
            get { return _p.Value.Multiply(_q.Value); }
        }

        public IBigInteger PrivateExponent
        {
            get { return _d.Value; }
        }

        public IBigInteger PrimeP
        {
            get { return _p.Value; }
        }

        public IBigInteger PrimeQ
        {
            get { return _q.Value; }
        }

        public IBigInteger PrimeExponentP
        {
            get { return _expP; }
        }

        public IBigInteger PrimeExponentQ
        {
            get { return _expQ; }
        }

        public IBigInteger CrtCoefficient
        {
            get { return _crt; }
        }

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format
        {
            get { return "PGP"; }
        }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WriteObjects(_d, _p, _q, _u);
        }
    }
}
