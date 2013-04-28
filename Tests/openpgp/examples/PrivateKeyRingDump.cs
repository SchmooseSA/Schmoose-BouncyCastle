using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Examples
{
    /**
    * Basic class which just lists the contents of the public key file passed
    * as an argument. If the file contains more than one "key ring" they are
    * listed in the order found.
    */
    public static class PrivateKeyRingDump
    {
        public static string GetAlgorithm(PublicKeyAlgorithmTag algId)
        {
            switch (algId)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                    return "RsaGeneral";
                case PublicKeyAlgorithmTag.RsaEncrypt:
                    return "RsaEncrypt";
                case PublicKeyAlgorithmTag.RsaSign:
                    return "RsaSign";
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    return "ElGamalEncrypt";
                case PublicKeyAlgorithmTag.Dsa:
                    return "DSA";
                case PublicKeyAlgorithmTag.Ecdh:
                    return "ECDH";
                case PublicKeyAlgorithmTag.Ecdsa:
                    return "ECDSA";
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    return "ElGamalGeneral";
                case PublicKeyAlgorithmTag.DiffieHellman:
                    return "DiffieHellman";
            }

            return "unknown";
        }

		public static void Main(string[] args)
		{
		    PgpSecretKeyRing secRings;
		    using (Stream fs = File.OpenRead(args[0]))
		    {
                secRings = new PgpSecretKeyRing(PgpUtilities.GetDecoderStream(fs));
		    }

            foreach (PgpSecretKey pgpSec in secRings.GetSecretKeys())
            {
                var privateKey = pgpSec.ExtractPrivateKey((args.Length > 1 ? args[1] : "").ToCharArray());
                
            }
        }
    }
}
