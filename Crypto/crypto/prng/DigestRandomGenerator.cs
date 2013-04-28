namespace Org.BouncyCastle.Crypto.Prng
{
	/**
	 * Random generation based on the digest with counter. Calling AddSeedMaterial will
	 * always increase the entropy of the hash.
	 * <p>
	 * Internal access to the digest is synchronized so a single one of these can be shared.
	 * </p>
	 */
	public class DigestRandomGenerator : IRandomGenerator
	{
		private const long CycleCount = 10;

		private long	_stateCounter;
		private long	_seedCounter;
		private readonly IDigest	_digest;
		private readonly byte[]	_state;
		private readonly byte[]	_seed;

		public DigestRandomGenerator(IDigest digest)
		{
			_digest = digest;

			_seed = new byte[digest.GetDigestSize()];
			_seedCounter = 1;

			_state = new byte[digest.GetDigestSize()];
			_stateCounter = 1;
		}

		public void AddSeedMaterial(byte[] inSeed)
		{
			lock (this)
			{
				DigestUpdate(inSeed);
				DigestUpdate(_seed);
				DigestDoFinal(_seed);
			}
		}

		public void AddSeedMaterial(long rSeed)
		{
			lock (this)
			{
				DigestAddCounter(rSeed);
				DigestUpdate(_seed);
				DigestDoFinal(_seed);
			}
		}

		public void NextBytes(byte[] bytes)
		{
			NextBytes(bytes, 0, bytes.Length);
		}

		public void NextBytes(
			byte[]	bytes,
			int		start,
			int		len)
		{
			lock (this)
			{
				var stateOff = 0;

				GenerateState();

				var end = start + len;
				for (var i = start; i < end; ++i)
				{
					if (stateOff == _state.Length)
					{
						GenerateState();
						stateOff = 0;
					}
					bytes[i] = _state[stateOff++];
				}
			}
		}

		private void CycleSeed()
		{
			DigestUpdate(_seed);
			DigestAddCounter(_seedCounter++);
			DigestDoFinal(_seed);
		}

		private void GenerateState()
		{
			DigestAddCounter(_stateCounter++);
			DigestUpdate(_state);
			DigestUpdate(_seed);
			DigestDoFinal(_state);

			if ((_stateCounter % CycleCount) == 0)
			{
				CycleSeed();
			}
		}

		private void DigestAddCounter(long seedVal)
		{
			var seed = (ulong)seedVal;
			for (var i = 0; i != 8; i++)
			{
				_digest.Update((byte)seed);
				seed >>= 8;
			}
		}

		private void DigestUpdate(byte[] inSeed)
		{
			_digest.BlockUpdate(inSeed, 0, inSeed.Length);
		}

		private void DigestDoFinal(byte[] result)
		{
			_digest.DoFinal(result, 0);
		}
	}
}
