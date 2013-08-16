using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
    public class ECDSAPublicBcpgKey : ECPublicBcpgKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ECDSAPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        public ECDSAPublicBcpgKey(BcpgInputStream bcpgIn)
            : base(bcpgIn, null) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ECDSAPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="point">The point.</param>
        /// <param name="oid">The oid.</param>
        public ECDSAPublicBcpgKey(ECPoint point, DerObjectIdentifier oid)
            : base(point, oid) { }
    }
}