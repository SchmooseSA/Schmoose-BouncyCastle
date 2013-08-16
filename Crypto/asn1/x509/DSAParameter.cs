using System;
using System.Collections;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    public class DsaParameter
        : Asn1Encodable
    {
        internal readonly DerInteger p, q, g;

		public static DsaParameter GetInstance(
            Asn1TaggedObject	obj,
            bool				explicitly)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, explicitly));
        }

		public static DsaParameter GetInstance(
            object obj)
        {
            if(obj == null || obj is DsaParameter)
            {
                return (DsaParameter) obj;
            }

			if(obj is Asn1Sequence)
            {
                return new DsaParameter((Asn1Sequence) obj);
            }

			throw new ArgumentException("Invalid DsaParameter: " + obj.GetType().Name);
        }

		public DsaParameter(
            IBigInteger p,
            IBigInteger q,
            IBigInteger g)
        {
            this.p = new DerInteger(p);
            this.q = new DerInteger(q);
            this.g = new DerInteger(g);
        }

		private DsaParameter(
            Asn1Sequence seq)
        {
			if (seq.Count != 3)
				throw new ArgumentException("Bad sequence size: " + seq.Count, "seq");

			this.p = DerInteger.GetInstance(seq[0]);
			this.q = DerInteger.GetInstance(seq[1]);
			this.g = DerInteger.GetInstance(seq[2]);
        }

        public IBigInteger P
		{
			get { return p.PositiveValue; }
		}

        public IBigInteger Q
		{
			get { return q.PositiveValue; }
		}

        public IBigInteger G
		{
			get { return g.PositiveValue; }
		}

		public override Asn1Object ToAsn1Object()
        {
			return new DerSequence(p, q, g);
        }
    }
}
