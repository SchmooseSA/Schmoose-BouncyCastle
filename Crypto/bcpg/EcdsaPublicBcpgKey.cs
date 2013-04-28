using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
    public class EcdsaPublicBcpgKey : EcPublicBcpgKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EcdsaPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        public EcdsaPublicBcpgKey(BcpgInputStream bcpgIn)
            : base(bcpgIn) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdsaPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="point">The point.</param>
        /// <param name="oid">The oid.</param>
        public EcdsaPublicBcpgKey(ECPoint point, DerObjectIdentifier oid)
            : base(point, oid) { }
    }
}