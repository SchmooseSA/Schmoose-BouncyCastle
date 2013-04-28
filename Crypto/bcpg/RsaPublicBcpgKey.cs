using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Base class for an RSA public key.</remarks>
    public class RsaPublicBcpgKey : BcpgObject, IBcpgPublicKey
    {
        private readonly MPInteger _n, _e;

        /// <summary>Construct an RSA public key from the passed in stream.</summary>
        public RsaPublicBcpgKey(BcpgInputStream bcpgIn)
        {
            _n = new MPInteger(bcpgIn);
            _e = new MPInteger(bcpgIn);
        }

        /// <param name="n">The modulus.</param>
        /// <param name="e">The public exponent.</param>
        public RsaPublicBcpgKey(IBigInteger n, IBigInteger e)
        {
            _n = new MPInteger(n);
            _e = new MPInteger(e);
        }

        public int BitStrength
        {
            get { return this.Modulus.BitLength; }
        }

        public IBigInteger PublicExponent
        {
            get { return _e.Value; }
        }

        public IBigInteger Modulus
        {
            get { return _n.Value; }
        }

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format
        {
            get { return "PGP"; }
        }
       
        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WriteObjects(_n, _e);
        }        
    }
}
