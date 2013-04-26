using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class EcdhPublicBcpgKey : EcPublicBcpgKey
    {
        private readonly byte _reserved;
        private readonly byte _hashFunctionId; 
        private readonly byte _symAlgorithmId;

        public EcdhPublicBcpgKey(BcpgInputStream bcpgIn)
            : base(bcpgIn)
        {
            var kdfParamters = this.ReadBytesOfEncodedLength(bcpgIn);
            if(kdfParamters.Length != 3)
                throw new InvalidDataException("kdf parameter size of 3 expected.");

            _reserved = kdfParamters[0];
            _hashFunctionId = kdfParamters[1];
            _symAlgorithmId = kdfParamters[2];
        }

        public byte Reserved
        {
            get { return _reserved; }
        }

        public byte HashFunctionId
        {
            get { return _hashFunctionId; }
        }

        public byte SymetricAlgorithmId
        {
            get { return _symAlgorithmId; }
        }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            base.Encode(bcpgOut);
            bcpgOut.WriteByte(0x3);
            bcpgOut.WriteByte(this.Reserved);
            bcpgOut.WriteByte(this.HashFunctionId);
            bcpgOut.WriteByte(this.SymetricAlgorithmId);
        }
    }
}
