using System;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class RsaPrivateCrtKeyParameters
		: RsaKeyParameters
    {
        private readonly IBigInteger e, p, q, dP, dQ, qInv;

		public RsaPrivateCrtKeyParameters(
            IBigInteger modulus,
            IBigInteger publicExponent,
            IBigInteger privateExponent,
            IBigInteger p,
            IBigInteger q,
            IBigInteger dP,
            IBigInteger dQ,
            IBigInteger qInv)
			: base(true, modulus, privateExponent)
        {
			ValidateValue(publicExponent, "publicExponent", "exponent");
			ValidateValue(p, "p", "P value");
			ValidateValue(q, "q", "Q value");
			ValidateValue(dP, "dP", "DP value");
			ValidateValue(dQ, "dQ", "DQ value");
			ValidateValue(qInv, "qInv", "InverseQ value");

			this.e = publicExponent;
            this.p = p;
            this.q = q;
            this.dP = dP;
            this.dQ = dQ;
            this.qInv = qInv;
        }

        public IBigInteger PublicExponent
        {
            get { return e; }
		}

        public IBigInteger P
		{
			get { return p; }
		}

        public IBigInteger Q
		{
			get { return q; }
		}

        public IBigInteger DP
		{
			get { return dP; }
		}

        public IBigInteger DQ
		{
			get { return dQ; }
		}

        public IBigInteger QInv
		{
			get { return qInv; }
		}

		public override bool Equals(
			object obj)
		{
			if (obj == this)
				return true;

			RsaPrivateCrtKeyParameters kp = obj as RsaPrivateCrtKeyParameters;

			if (kp == null)
				return false;

			return kp.DP.Equals(dP)
				&& kp.DQ.Equals(dQ)
				&& kp.Exponent.Equals(this.Exponent)
				&& kp.Modulus.Equals(this.Modulus)
				&& kp.P.Equals(p)
				&& kp.Q.Equals(q)
				&& kp.PublicExponent.Equals(e)
				&& kp.QInv.Equals(qInv);
		}

		public override int GetHashCode()
		{
			return DP.GetHashCode() ^ DQ.GetHashCode() ^ Exponent.GetHashCode() ^ Modulus.GetHashCode()
				^ P.GetHashCode() ^ Q.GetHashCode() ^ PublicExponent.GetHashCode() ^ QInv.GetHashCode();
		}

        private static void ValidateValue(IBigInteger x, string name, string desc)
		{
			if (x == null)
				throw new ArgumentNullException(name);
			if (x.SignValue <= 0)
				throw new ArgumentException("Not a valid RSA " + desc, name);
		}
	}
}
