namespace Org.BouncyCastle.Math.EC.Multiplier
{
	/**
	* Class holding precomputation data for the WNAF (Window Non-Adjacent Form)
	* algorithm.
	*/
	internal class WNafPreCompInfo : IPreCompInfo 
	{
		/**
		* Array holding the precomputed <code>ECPoint</code>s used for the Window
		* NAF multiplication in <code>
		* {@link org.bouncycastle.math.ec.multiplier.WNafMultiplier.multiply()
		* WNafMultiplier.multiply()}</code>.
		*/
		private ECPoint[] _preComp;

		/**
		* Holds an <code>ECPoint</code> representing twice(this). Used for the
		* Window NAF multiplication in <code>
		* {@link org.bouncycastle.math.ec.multiplier.WNafMultiplier.multiply()
		* WNafMultiplier.multiply()}</code>.
		*/
		private ECPoint _twiceP;

		internal ECPoint[] GetPreComp()
		{
			return _preComp;
		}

		internal void SetPreComp(ECPoint[] preComp)
		{
			_preComp = preComp;
		}

		internal ECPoint GetTwiceP()
		{
			return _twiceP;
		}

		internal void SetTwiceP(ECPoint twiceThis)
		{
			_twiceP = twiceThis;
		}
	}
}
