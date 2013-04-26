using System;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    public abstract class EcPublicBcpgKey : BcpgObject, IBcpgKey
    {
        public static readonly byte[] NistCurveP256Oid = new byte[] { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
        public static readonly byte[] NistCurveP384Oid = new byte[] { 0x2B, 0x81, 0x04, 0x00, 0x22 };
        public static readonly byte[] NistCurveP521Oid = new byte[] { 0x2B, 0x81, 0x04, 0x00, 0x23 };

        private readonly MPInteger _point;
        private readonly byte[] _oid;

        /// <summary>
        /// Initializes a new instance of the <see cref="EcPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        protected EcPublicBcpgKey(BcpgInputStream bcpgIn)
        {
            _oid = this.ReadBytesOfEncodedLength(bcpgIn);
            _point = new MPInteger(bcpgIn);
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
        public byte[] Oid
        {
            get { return _oid; }
        }

        /// <summary>
        /// Gets the EC point representing a public key.
        /// </summary>
        /// <value>
        /// The point.
        /// </value>
        public IBigInteger Point
        {
            get { return _point.Value; }
        }

        /// <summary>
        /// Encodes the specified BCPG out.
        /// </summary>
        /// <param name="bcpgOut">The BCPG out.</param>
        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WriteByte((byte)this.Oid.Length);
            bcpgOut.Write(this.Oid, 0, this.Oid.Length);
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
                throw new NotSupportedException("future extensions not yet implemented.");

            var buffer = new byte[length];
            bcpgIn.Read(buffer, 0, length);
            return buffer;
        }
    }
}
