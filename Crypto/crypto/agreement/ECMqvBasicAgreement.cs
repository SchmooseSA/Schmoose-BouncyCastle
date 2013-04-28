using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Agreement
{
	public class ECMqvBasicAgreement : IBasicAgreement
	{
		protected internal MqvPrivateParameters PrivParams;

		public void Init(ICipherParameters parameters)
		{
			if (parameters is ParametersWithRandom)
			{
				parameters = ((ParametersWithRandom)parameters).Parameters;
			}

			this.PrivParams = (MqvPrivateParameters)parameters;
		}

		public virtual IBigInteger CalculateAgreement(ICipherParameters pubKey)
		{
			var pubParams = (MqvPublicParameters)pubKey;

			var staticPrivateKey = PrivParams.StaticPrivateKey;

			var agreement = CalculateMqvAgreement(staticPrivateKey.Parameters, staticPrivateKey,
				PrivParams.EphemeralPrivateKey, PrivParams.EphemeralPublicKey,
				pubParams.StaticPublicKey, pubParams.EphemeralPublicKey);

			return agreement.X.ToBigInteger();
		}
		
		// The ECMQV Primitive as described in SEC-1, 3.4
		private static ECPoint CalculateMqvAgreement(
			ECDomainParameters		parameters,
			ECPrivateKeyParameters	d1U,
			ECPrivateKeyParameters	d2U,
			ECPublicKeyParameters	q2U,
			ECPublicKeyParameters	q1V,
			ECPublicKeyParameters	q2V)
		{
            var n = parameters.N;
			var e = (n.BitLength + 1) / 2;
            var powE = BigInteger.One.ShiftLeft(e);

			// The Q2U public key is optional
		    var q = q2U == null ? parameters.G.Multiply(d2U.D) : q2U.Q;

			var x = q.X.ToBigInteger();
			var xBar = x.Mod(powE);
			var q2UBar = xBar.SetBit(e);
			var s = d1U.D.Multiply(q2UBar).Mod(n).Add(d2U.D).Mod(n);

			var xPrime = q2V.Q.X.ToBigInteger();
			var xPrimeBar = xPrime.Mod(powE);
			var q2VBar = xPrimeBar.SetBit(e);

			var hs = parameters.H.Multiply(s).Mod(n);

			//ECPoint p = Q1V.Q.Multiply(Q2VBar).Add(Q2V.Q).Multiply(hs);
			var p = ECAlgorithms.SumOfTwoMultiplies(
				q1V.Q, q2VBar.Multiply(hs).Mod(n), q2V.Q, hs);

			if (p.IsInfinity)
				throw new InvalidOperationException("Infinity is not a valid agreement value for MQV");

			return p;
		}
	}
}
