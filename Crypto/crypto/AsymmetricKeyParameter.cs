namespace Org.BouncyCastle.Crypto
{
    public class AsymmetricKeyParameter
		: IAsymmetricKeyParameter
    {
        private readonly bool privateKey;

        public AsymmetricKeyParameter(
            bool privateKey)
        {
            this.privateKey = privateKey;
        }

		public bool IsPrivate
        {
            get { return privateKey; }
        }

		public override bool Equals(
			object obj)
		{
            var other = obj as IAsymmetricKeyParameter;

			return other != null && Equals(other);
		}

		protected bool Equals(
			IAsymmetricKeyParameter other)
		{
			return privateKey == other.IsPrivate;
		}

		public override int GetHashCode()
		{
			return privateKey.GetHashCode();
		}
    }
}
