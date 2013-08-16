namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving signature creation time.
    */
    public class PreferredAlgorithms : SignatureSubpacket
    {
        private static byte[] IntToByteArray(int[] v)
        {
            var data = new byte[v.Length];

            for (var i = 0; i != v.Length; i++)
            {
                data[i] = (byte)v[i];
            }

            return data;
        }

        public PreferredAlgorithms(SignatureSubpacketTag type,bool critical,byte[] data)
            : base(type, critical, data)
        {
        }

        public PreferredAlgorithms(SignatureSubpacketTag type,bool critical,int[] preferences)
            : base(type, critical, IntToByteArray(preferences))
        {
        }

        public int[] GetPreferences()
        {
            var v = new int[Data.Length];

            for (var i = 0; i != v.Length; i++)
            {
                v[i] = Data[i] & 0xff;
            }

            return v;
        }
    }
}
