using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Base class for an ElGamal secret key.
    /// </summary>
    public class ElGamalSecretBcpgKey : BcpgObject, IBcpgKey
	{
		private readonly MPInteger _x;

		/// <summary>
        /// Initializes a new instance of the <see cref="ElGamalSecretBcpgKey"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
		public ElGamalSecretBcpgKey(BcpgInputStream bcpgIn)
		{
            _x = new MPInteger(bcpgIn);
		}

		/// <summary>
        /// Initializes a new instance of the <see cref="ElGamalSecretBcpgKey"/> class.
        /// </summary>
        /// <param name="x">The x.</param>
		public ElGamalSecretBcpgKey(IBigInteger x)
		{
            _x = new MPInteger(x);
		}

        /// <summary>
        /// The format, as a string, always "PGP".
        /// </summary>
        /// <returns>"RAW" or "PGP".</returns>
		public string Format
		{
			get { return "PGP"; }
		}

        /// <summary>
        /// Gets the X.
        /// </summary>
        /// <value>
        /// The X.
        /// </value>
        public IBigInteger X
		{
            get { return _x.Value; }
		}

        /// <summary>
        /// Return the standard PGP encoding of the key.
        /// </summary>
        /// <returns></returns>
		public override byte[] GetEncoded()
		{
			try
			{
				return base.GetEncoded();
			}
			catch (Exception)
			{
				return null;
			}
		}

		public override void Encode(IBcpgOutputStream bcpgOut)
		{
            bcpgOut.WriteObject(_x);
		}
	}
}
