namespace Org.BouncyCastle.Math.EC.Multiplier
{
	/**
	* Class holding precomputation data for the WTNAF (Window
	* <code>&#964;</code>-adic Non-Adjacent Form) algorithm.
	*/
	internal class WTauNafPreCompInfo
		: IPreCompInfo
	{
		/**
		* Array holding the precomputed <code>F2mPoint</code>s used for the
		* WTNAF multiplication in <code>
		* {@link org.bouncycastle.math.ec.multiplier.WTauNafMultiplier.multiply()
		* WTauNafMultiplier.multiply()}</code>.
		*/
		private readonly F2MPoint[] _preComp;

		/**
		* Constructor for <code>WTauNafPreCompInfo</code>
		* @param preComp Array holding the precomputed <code>F2mPoint</code>s
		* used for the WTNAF multiplication in <code>
		* {@link org.bouncycastle.math.ec.multiplier.WTauNafMultiplier.multiply()
		* WTauNafMultiplier.multiply()}</code>.
		*/
		internal WTauNafPreCompInfo(F2MPoint[] preComp)
		{
			_preComp = preComp;
		}

		/**
		* @return the array holding the precomputed <code>F2mPoint</code>s
		* used for the WTNAF multiplication in <code>
		* {@link org.bouncycastle.math.ec.multiplier.WTauNafMultiplier.multiply()
		* WTauNafMultiplier.multiply()}</code>.
		*/
		internal F2MPoint[] GetPreComp()
		{
			return _preComp;
		}
	}
}
