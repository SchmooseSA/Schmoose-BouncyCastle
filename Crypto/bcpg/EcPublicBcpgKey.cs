using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
    public abstract class ECPublicBcpgKey : BcpgObject, IBcpgPublicKey
    {
        private readonly DerObjectIdentifier _oid;
        private readonly ECPoint _point;

        /// <summary>
        /// Initializes a new instance of the <see cref="ECPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        /// <param name="oid">The OID.</param>
        protected ECPublicBcpgKey(BcpgInputStream bcpgIn, DerObjectIdentifier oid)
        {
            _oid = oid ?? new DerObjectIdentifier(this.ReadBytesOfEncodedLength(bcpgIn));
            _point = DecodePoint(new MPInteger(bcpgIn).Value, _oid);
        }
        
        /// <summary>
        /// Initializes a new instance of the <see cref="ECPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="point">The point.</param>
        /// <param name="oid">The oid.</param>
        /// <exception cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException">Only FPCurves are supported.</exception>
        protected ECPublicBcpgKey(ECPoint point, DerObjectIdentifier oid)
        {
            _oid = oid;
            _point = point;
        }

        protected ECPublicBcpgKey(IBigInteger encodedPoint, DerObjectIdentifier oid)
        {
            _oid = oid;
            _point = DecodePoint(encodedPoint, _oid);
        }

        /// <summary>
        /// Gets the bit strength.
        /// </summary>
        /// <value>
        /// The bit strength.
        /// </value>
        public int BitStrength 
        {
            get { return _point.Curve.FieldSize; }
        }

        /// <summary>
        /// The base format for this key - in the case of the symmetric keys it will generally
        /// be raw indicating that the key is just a straight byte representation, for an asymmetric
        /// key the format will be PGP, indicating the key is a string of MPIs encoded in PGP format.
        /// </summary>
        /// <returns>"RAW" or "PGP".</returns>
        public string Format
        {
            get { return "PGP"; }
        }

        /// <summary>
        /// Gets the curve oid.
        /// </summary>
        /// <value>
        /// The oid.
        /// </value>
        public DerObjectIdentifier Oid
        {
            get { return _oid; }
        }

        public ECPoint Point 
        {
            get { return _point; }
        }

        /// <summary>
        /// Encodes the specified BCPG out.
        /// </summary>
        /// <param name="bcpgOut">The BCPG out.</param>
        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            var oid = this.Oid.ToBytes();
            bcpgOut.WriteByte((byte)oid.Length);
            bcpgOut.Write(oid, 0, oid.Length);

            var point = new MPInteger(new BigInteger(1, _point.GetEncoded()));
            bcpgOut.WriteObject(point);
        }

        /// <summary>
        /// Reads the numver of bytes encoded.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        /// <returns></returns>
        /// <exception cref="System.NotSupportedException">future extensions not yet implemented.</exception>
        protected byte[] ReadBytesOfEncodedLength(BcpgInputStream bcpgIn)
        {
            var length = bcpgIn.ReadByte();
            if (length == 0 || length == 0xFF)
                throw new PgpException("future extensions not yet implemented.");

            var buffer = new byte[length];
            bcpgIn.ReadFully(buffer);
            return buffer;
        }

        private static ECPoint DecodePoint(IBigInteger encodedPoint, DerObjectIdentifier oid)
        {
            var curve = ECKeyPairGenerator.FindECCurveByOid(oid);
            if (curve == null)
                throw new PgpException(oid.Id + " does not match any known curve.");
            if (!(curve.Curve is FPCurve))
                throw new PgpException("Only FPCurves are supported.");

            return curve.Curve.DecodePoint(encodedPoint.ToByteArrayUnsigned());
        }
    }
}