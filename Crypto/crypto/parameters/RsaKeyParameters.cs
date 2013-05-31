using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public class RsaKeyParameters
		: AsymmetricKeyParameter
    {
        private readonly IBigInteger modulus;
        private readonly IBigInteger exponent;

		public RsaKeyParameters(
            bool		isPrivate,
            IBigInteger modulus,
            IBigInteger exponent)
			: base(isPrivate)
        {
			if (modulus == null)
				throw new ArgumentNullException("modulus");
			if (exponent == null)
				throw new ArgumentNullException("exponent");
			if (modulus.SignValue <= 0)
				throw new ArgumentException(@"Not a valid RSA modulus", "modulus");
			if (exponent.SignValue <= 0)
				throw new ArgumentException(@"Not a valid RSA exponent", "exponent");

			this.modulus = modulus;
			this.exponent = exponent;
        }

        public IBigInteger Modulus
        {
            get { return modulus; }
        }

        public IBigInteger Exponent
        {
            get { return exponent; }
        }

		public override bool Equals(
			object obj)
        {
            RsaKeyParameters kp = obj as RsaKeyParameters;

			if (kp == null)
			{
				return false;
			}

			return kp.IsPrivate == this.IsPrivate
				&& kp.Modulus.Equals(this.modulus)
				&& kp.Exponent.Equals(this.exponent);
        }

		public override int GetHashCode()
        {
            return modulus.GetHashCode() ^ exponent.GetHashCode() ^ IsPrivate.GetHashCode();
        }
    }
}
