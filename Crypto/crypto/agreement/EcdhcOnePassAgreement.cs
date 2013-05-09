using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Agreement
{
    
    public class EcdhcOnePassAgreement : IBasicAgreement
    {
        public void Init(ICipherParameters parameters)
        {
            throw new System.NotImplementedException();
        }

        public IBigInteger CalculateAgreement(ICipherParameters pubKey)
        {
            throw new System.NotImplementedException();
        }
    }

}
