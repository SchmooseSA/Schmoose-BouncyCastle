using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
    public abstract class EcPublicBcpgKey : BcpgObject, IBcpgPublicKey
    {
        private readonly MPInteger _point;
        private readonly DerObjectIdentifier _oid;

        /// <summary>
        /// Initializes a new instance of the <see cref="EcPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        protected EcPublicBcpgKey(BcpgInputStream bcpgIn)
        {
            _oid = new DerObjectIdentifier(this.ReadBytesOfEncodedLength(bcpgIn));
            _point = new MPInteger(bcpgIn);

            this.Initialize();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EcPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="point">The point.</param>
        /// <param name="oid">The oid.</param>
        /// <exception cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException">Only FPCurves are supported.</exception>
        protected EcPublicBcpgKey(ECPoint point, DerObjectIdentifier oid)
        {
            _oid = oid;

            var x = point.X.ToBigInteger().ToByteArrayUnsigned();
            var y = point.Y.ToBigInteger().ToByteArrayUnsigned();

            var bytes = new byte[1 + x.Length + y.Length];
            bytes[0] = 4;
            Buffer.BlockCopy(x, 0, bytes, 1, x.Length);
            Buffer.BlockCopy(y, 0, bytes, 1 + x.Length, y.Length);
            _point = new MPInteger(new BigInteger(bytes));

            this.Initialize();
        }

        /// <summary>
        /// Gets the bit strength.
        /// </summary>
        /// <value>
        /// The bit strength.
        /// </value>
        public int BitStrength { get; private set; }

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

        public ECPoint Point { get; private set; }

        /// <summary>
        /// Encodes the specified BCPG out.
        /// </summary>
        /// <param name="bcpgOut">The BCPG out.</param>
        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            var oid = this.Oid.ToBytes();
            bcpgOut.WriteByte((byte)oid.Length);
            bcpgOut.Write(oid, 0, oid.Length);
            bcpgOut.WriteObject(_point);
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

        private void Initialize()
        {
            var curve = ECKeyPairGenerator.FindECCurveByOid(this.Oid);
            if (curve == null)
                throw new PgpException(this.Oid.Id + " does not match any known curve.");
            if (!(curve.Curve is FPCurve))
                throw new PgpException("Only FPCurves are supported.");

            this.BitStrength = curve.Curve.FieldSize;

            var len = (this.BitStrength + 8 - 1) / 8; // fast ceiling

            var bytes = _point.Value.ToByteArrayUnsigned();
            if (bytes.Length - 1 == len)
                throw new PgpException("Compressed ec points are not yet supported.");
            if (bytes.Length - 1 != 2 * len)
                throw new PgpException("Invalid data length.");
            if (bytes[0] != 4)
                throw new PgpException("4 was expected for w but was " + bytes[0]);
            this.Point = new FPPoint(curve.Curve,
                new FPFieldElement(curve.N, new BigInteger(bytes, 1, len)),
                new FPFieldElement(curve.N, new BigInteger(bytes, 1 + len, len)));
        }
    }
}