using Org.BouncyCastle.Asn1;
using System;
using System.Collections;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class DHParameter
        : Asn1Encodable
    {
        internal DerInteger p, g, l;

		public DHParameter(
            IBigInteger	p,
            IBigInteger g,
            int			l)
        {
            this.p = new DerInteger(p);
            this.g = new DerInteger(g);

			if (l != 0)
            {
                this.l = new DerInteger(l);
            }
        }

		public DHParameter(
            Asn1Sequence seq)
        {
            IEnumerator e = seq.GetEnumerator();

			e.MoveNext();
            p = (DerInteger)e.Current;

			e.MoveNext();
            g = (DerInteger)e.Current;

			if (e.MoveNext())
            {
                l = (DerInteger) e.Current;
            }
        }

        public IBigInteger P
		{
			get { return p.PositiveValue; }
		}

        public IBigInteger G
		{
			get { return g.PositiveValue; }
		}

        public IBigInteger L
		{
            get { return l == null ? null : l.PositiveValue; }
        }

		public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(p, g);

			if (this.l != null)
            {
                v.Add(l);
            }

			return new DerSequence(v);
        }
    }
}
