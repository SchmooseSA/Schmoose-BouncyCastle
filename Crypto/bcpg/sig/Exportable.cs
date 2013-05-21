namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving signature creation time.
    */
    public class Exportable : SignatureSubpacket
    {
        private static byte[] BooleanToByteArray(bool val)
        {
            var data = new byte[1];

            if (val)
            {
                data[0] = 1;
                return data;
            }
            return data;
        }

        public Exportable(bool critical, byte[] data)
            : base(SignatureSubpacketTag.Exportable, critical, data)
        {
        }

        public Exportable(bool critical, bool isExportable)
            : base(SignatureSubpacketTag.Exportable, critical, BooleanToByteArray(isExportable))
        {
        }

        public bool IsExportable()
        {
            return Data[0] != 0;
        }
    }
}
