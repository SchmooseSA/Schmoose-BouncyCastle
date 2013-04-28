using System;
using System.IO;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Examples
{
    /**
    * A simple utility class that Generates a RSA PgpPublicKey/PgpSecretKey pair.
    * <p>
    * usage: RsaKeyRingGenerator [-a] identity passPhrase</p>
    * <p>
    * Where identity is the name to be associated with the public key. The keys are placed
    * in the files pub.[asc|bpg] and secret.[asc|bpg].</p>
    */
    public static class EcKeyRingGenerator
    {
        private static void ExportKeyPair(
            Stream secretOut,
            Stream publicOut,
            IAsymmetricCipherKeyPair signingKey,
            IAsymmetricCipherKeyPair encryptionKey,
            string identity,
            char[] passPhrase,
            bool armor,
            ISecureRandom random)
        {
            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }

            var masterKey = new PgpKeyPair(PublicKeyAlgorithmTag.Ecdsa, signingKey, DateTime.UtcNow);
            var subKey = new PgpKeyPair(PublicKeyAlgorithmTag.Ecdh, encryptionKey, DateTime.UtcNow);
            var keyRingGenerator = new PgpKeyRingGenerator(
                PgpSignature.PositiveCertification, masterKey, identity,
                SymmetricKeyAlgorithmTag.Aes256, passPhrase, true, null, null, random);
            keyRingGenerator.AddSubKey(subKey);

            keyRingGenerator.GenerateSecretKeyRing().Encode(secretOut);
            
            if (armor)
            {
                secretOut.Close();
                publicOut = new ArmoredOutputStream(publicOut);
            }

            keyRingGenerator.GeneratePublicKeyRing().Encode(publicOut);
            {
                publicOut.Close();
            }
        }

        public static int Main(string[] args)
        {
            var secureRandom = new SecureRandom();
            var ecParams = new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, secureRandom);
            var ecdsa = GeneratorUtilities.GetKeyPairGenerator("ECDSA");
            ecdsa.Init(ecParams);
            var ecdh = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            ecdh.Init(ecParams);


            IAsymmetricCipherKeyPair kpEcdsa = ecdsa.GenerateKeyPair();
            IAsymmetricCipherKeyPair kpEcdh = ecdh.GenerateKeyPair();

            if (args.Length < 2)
            {
                Console.WriteLine("EcKeyRingGenerator [-a] identity passPhrase");
                return 0;
            }

            Stream out1, out2;
            if (args[0].Equals("-a"))
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("EcKeyRingGenerator [-a] identity passPhrase");
                    return 0;
                }

                out1 = File.Create("secret.asc");
                out2 = File.Create("pub.asc");

                ExportKeyPair(out1, out2, kpEcdsa, kpEcdh, args[1], args[2].ToCharArray(), true, secureRandom);
            }
            else
            {
                out1 = File.Create("secret.bpg");
                out2 = File.Create("pub.bpg");

                ExportKeyPair(out1, out2, kpEcdsa, kpEcdh, args[0], args[1].ToCharArray(), false, secureRandom);
            }
            out1.Close();
            out2.Close();
            return 0;
        }
    }
}
