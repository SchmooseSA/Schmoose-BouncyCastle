using System;
using System.Collections.Generic;
using System.Globalization;
using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Math.EC.Tests
{
	/**
	 * Test class for {@link org.bouncycastle.math.ec.ECPoint ECPoint}. All
	 * literature values are taken from "Guide to elliptic curve cryptography",
	 * Darrel Hankerson, Alfred J. Menezes, Scott Vanstone, 2004, Springer-Verlag
	 * New York, Inc.
	 */
	[TestFixture]
	public class ECPointTest
	{
		/**
		 * Random source used to generate random points
		 */
		private readonly SecureRandom _secRand = new SecureRandom();

//		private ECPointTest.Fp fp = null;

//		private ECPointTest.F2m f2m = null;

		/**
		 * Nested class containing sample literature values for <code>Fp</code>.
		 */
		public class Fp
		{
			internal static readonly IBigInteger Q = new BigInteger("29");

			internal static readonly IBigInteger A = new BigInteger("4");

			internal static readonly IBigInteger B = new BigInteger("20");

			internal static readonly FPCurve Curve = new FPCurve(Q, A, B);

			internal static readonly FPPoint Infinity = (FPPoint) Curve.Infinity;

			internal static readonly int[] PointSource = { 5, 22, 16, 27, 13, 6, 14, 6 };

			internal static FPPoint[] P = new FPPoint[PointSource.Length / 2];

			/**
			 * Creates the points on the curve with literature values.
			 */
			internal static void CreatePoints()
			{
				for (var i = 0; i < PointSource.Length / 2; i++)
				{
					var x = new FPFieldElement(Q, new BigInteger(PointSource[2 * i].ToString(CultureInfo.InvariantCulture)));
					var y = new FPFieldElement(Q, new BigInteger(PointSource[2 * i + 1].ToString(CultureInfo.InvariantCulture)));
					P[i] = new FPPoint(Curve, x, y);
				}
			}
		}

		/**
		 * Nested class containing sample literature values for <code>F2m</code>.
		 */
		public class F2M
		{
			// Irreducible polynomial for TPB z^4 + z + 1
			internal const int M = 4;

			internal const int K1 = 1;

			// a = z^3
			internal static readonly F2MFieldElement ATpb = new F2MFieldElement(M, K1,
				new BigInteger("8", 16));

			// b = z^3 + 1
			internal static readonly F2MFieldElement BTpb = new F2MFieldElement(M, K1,
				new BigInteger("9", 16));

			internal static readonly F2MCurve Curve = new F2MCurve(M, K1, ATpb
				.ToBigInteger(), BTpb.ToBigInteger());

			internal static readonly F2MPoint Infinity = (F2MPoint) Curve.Infinity;

			internal static readonly string[] PointSource = { "2", "f", "c", "c", "1", "1", "b", "2" };

			internal static F2MPoint[] P = new F2MPoint[PointSource.Length / 2];

			/**
			 * Creates the points on the curve with literature values.
			 */
			internal static void CreatePoints()
			{
				for (var i = 0; i < PointSource.Length / 2; i++)
				{
					var x = new F2MFieldElement(M, K1, new BigInteger(PointSource[2 * i], 16));
					var y = new F2MFieldElement(M, K1, new BigInteger(PointSource[2 * i + 1], 16));
					P[i] = new F2MPoint(Curve, x, y);
				}
			}
		}

		[SetUp]
		public void SetUp()
		{
//			fp = new ECPointTest.Fp();
			Fp.CreatePoints();

//			f2m = new ECPointTest.F2m();
			F2M.CreatePoints();
		}

		/**
		 * Tests, if inconsistent points can be created, i.e. points with exactly
		 * one null coordinate (not permitted).
		 */
		[Test]
		public void TestPointCreationConsistency()
		{
			try
			{
				var bad = new FPPoint(Fp.Curve, new FPFieldElement(
					Fp.Q, new BigInteger("12")), null);
				Assert.Fail();
			}
			catch (ArgumentException)
			{
				// Expected
			}

			try
			{
				var bad = new FPPoint(Fp.Curve, null,
					new FPFieldElement(Fp.Q, new BigInteger("12")));
				Assert.Fail();
			}
			catch (ArgumentException)
			{
				// Expected
			}

			try
			{
				var bad = new F2MPoint(F2M.Curve, new F2MFieldElement(
					F2M.M, F2M.K1, new BigInteger("1011")), null);
				Assert.Fail();
			}
			catch (ArgumentException)
			{
				// Expected
			}

			try
			{
				var bad = new F2MPoint(F2M.Curve, null,
					new F2MFieldElement(F2M.M, F2M.K1,
					new BigInteger("1011")));
				Assert.Fail();
			}
			catch (ArgumentException)
			{
				// Expected
			}
		}

		/**
		 * Tests <code>ECPoint.add()</code> against literature values.
		 *
		 * @param p
		 *            The array of literature values.
		 * @param infinity
		 *            The point at infinity on the respective curve.
		 */
		private static void ImplTestAdd(IList<ECPoint> p, ECPoint infinity)
		{
			Assert.AreEqual(p[2], p[0].Add(p[1]), "p0 plus p1 does not equal p2");
			Assert.AreEqual(p[2], p[1].Add(p[0]), "p1 plus p0 does not equal p2");
			foreach (var t in p)
			{
			    Assert.AreEqual(t, t.Add(infinity), "Adding infinity failed");
			    Assert.AreEqual(t, infinity.Add(t), "Adding to infinity failed");
			}
		}

		/**
		 * Calls <code>implTestAdd()</code> for <code>Fp</code> and
		 * <code>F2m</code>.
		 */
		[Test]
		public void TestAdd()
		{
			ImplTestAdd(Fp.P, Fp.Infinity);
			ImplTestAdd(F2M.P, F2M.Infinity);
		}

		/**
		 * Tests <code>ECPoint.twice()</code> against literature values.
		 *
		 * @param p
		 *            The array of literature values.
		 */
		private static void ImplTestTwice(IList<ECPoint> p)
		{
			Assert.AreEqual(p[3], p[0].Twice(), "Twice incorrect");
			Assert.AreEqual(p[3], p[0].Add(p[0]), "Add same point incorrect");
		}

		/**
		 * Calls <code>implTestTwice()</code> for <code>Fp</code> and
		 * <code>F2m</code>.
		 */
		[Test]
		public void TestTwice()
		{
			ImplTestTwice(Fp.P);
			ImplTestTwice(F2M.P);
		}

		/**
		 * Goes through all points on an elliptic curve and checks, if adding a
		 * point <code>k</code>-times is the same as multiplying the point by
		 * <code>k</code>, for all <code>k</code>. Should be called for points
		 * on very small elliptic curves only.
		 *
		 * @param p
		 *            The base point on the elliptic curve.
		 * @param infinity
		 *            The point at infinity on the elliptic curve.
		 */
		private static void ImplTestAllPoints(ECPoint p, ECPoint infinity)
		{
			var adder = infinity;
		    var i = 1;
			do
			{
				adder = adder.Add(p);
				var multiplier = p.Multiply(new BigInteger(i.ToString(CultureInfo.InvariantCulture)));
				Assert.AreEqual(adder, multiplier,
					"Results of add() and multiply() are inconsistent " + i);
				i++;
			}
			while (!(adder.Equals(infinity)));
		}

		/**
		 * Calls <code>implTestAllPoints()</code> for the small literature curves,
		 * both for <code>Fp</code> and <code>F2m</code>.
		 */
		[Test]
		public void TestAllPoints()
		{
		    foreach (var t in Fp.P)
		    {
		        ImplTestAllPoints(t, Fp.Infinity);
		    }

		    foreach (var t in F2M.P)
		    {
		        ImplTestAllPoints(t, F2M.Infinity);
		    }
		}

	    /**
		 * Simple shift-and-add multiplication. Serves as reference implementation
		 * to verify (possibly faster) implementations in
		 * {@link org.bouncycastle.math.ec.ECPoint ECPoint}.
		 *
		 * @param p
		 *            The point to multiply.
		 * @param k
		 *            The multiplier.
		 * @return The result of the point multiplication <code>kP</code>.
		 */
		private ECPoint multiply(ECPoint p, IBigInteger k)
		{
			ECPoint q = p.Curve.Infinity;
			int t = k.BitLength;
			for (int i = 0; i < t; i++)
			{
				if (k.TestBit(i))
				{
					q = q.Add(p);
				}
				p = p.Twice();
			}
			return q;
		}

		/**
		 * Checks, if the point multiplication algorithm of the given point yields
		 * the same result as point multiplication done by the reference
		 * implementation given in <code>multiply()</code>. This method chooses a
		 * random number by which the given point <code>p</code> is multiplied.
		 *
		 * @param p
		 *            The point to be multiplied.
		 * @param numBits
		 *            The bitlength of the random number by which <code>p</code>
		 *            is multiplied.
		 */
		private void ImplTestMultiply(ECPoint p, int numBits)
		{
			var k = new BigInteger(numBits, _secRand);
			var reff = multiply(p, k);
			var q = p.Multiply(k);
			Assert.AreEqual(reff, q, "ECPoint.multiply is incorrect");
		}

		/**
		 * Checks, if the point multiplication algorithm of the given point yields
		 * the same result as point multiplication done by the reference
		 * implementation given in <code>multiply()</code>. This method tests
		 * multiplication of <code>p</code> by every number of bitlength
		 * <code>numBits</code> or less.
		 *
		 * @param p
		 *            The point to be multiplied.
		 * @param numBits
		 *            Try every multiplier up to this bitlength
		 */
		private void ImplTestMultiplyAll(ECPoint p, int numBits)
		{
			var bound = BigInteger.Two.Pow(numBits);
			var k = BigInteger.Zero;

			do
			{
				var reff = multiply(p, k);
				var q = p.Multiply(k);
				Assert.AreEqual(reff, q, "ECPoint.multiply is incorrect");
				k = k.Add(BigInteger.One);
			}
			while (k.CompareTo(bound) < 0);
		}

		/**
		 * Tests <code>ECPoint.add()</code> and <code>ECPoint.subtract()</code>
		 * for the given point and the given point at infinity.
		 *
		 * @param p
		 *            The point on which the tests are performed.
		 * @param infinity
		 *            The point at infinity on the same curve as <code>p</code>.
		 */
		private void implTestAddSubtract(ECPoint p, ECPoint infinity)
		{
			Assert.AreEqual(p.Twice(), p.Add(p), "Twice and Add inconsistent");
			Assert.AreEqual(p, p.Twice().Subtract(p), "Twice p - p is not p");
			Assert.AreEqual(infinity, p.Subtract(p), "p - p is not infinity");
			Assert.AreEqual(p, p.Add(infinity), "p plus infinity is not p");
			Assert.AreEqual(p, infinity.Add(p), "infinity plus p is not p");
			Assert.AreEqual(infinity, infinity.Add(infinity), "infinity plus infinity is not infinity ");
		}

		/**
		 * Calls <code>implTestAddSubtract()</code> for literature values, both
		 * for <code>Fp</code> and <code>F2m</code>.
		 */
		[Test]
		public void TestAddSubtractMultiplySimple()
		{
			for (var iFp = 0; iFp < Fp.PointSource.Length / 2; iFp++)
			{
				implTestAddSubtract(Fp.P[iFp], Fp.Infinity);

				// Could be any numBits, 6 is chosen at will
				ImplTestMultiplyAll(Fp.P[iFp], 6);
				ImplTestMultiplyAll(Fp.Infinity, 6);
			}

			for (var iF2M = 0; iF2M < F2M.PointSource.Length / 2; iF2M++)
			{
				implTestAddSubtract(F2M.P[iF2M], F2M.Infinity);

				// Could be any numBits, 6 is chosen at will
				ImplTestMultiplyAll(F2M.P[iF2M], 6);
				ImplTestMultiplyAll(F2M.Infinity, 6);
			}
		}

		/**
		 * Test encoding with and without point compression.
		 *
		 * @param p
		 *            The point to be encoded and decoded.
		 */
		private void implTestEncoding(ECPoint p)
		{
			// Not Point Compression
			ECPoint unCompP;

			// Point compression
			ECPoint compP;

			if (p is FPPoint)
			{
				unCompP = new FPPoint(p.Curve, p.X, p.Y, false);
				compP = new FPPoint(p.Curve, p.X, p.Y, true);
			}
			else
			{
				unCompP = new F2MPoint(p.Curve, p.X, p.Y, false);
				compP = new F2MPoint(p.Curve, p.X, p.Y, true);
			}

			byte[] unCompBarr = unCompP.GetEncoded();
			ECPoint decUnComp = p.Curve.DecodePoint(unCompBarr);
			Assert.AreEqual(p, decUnComp, "Error decoding uncompressed point");

			byte[] compBarr = compP.GetEncoded();
			ECPoint decComp = p.Curve.DecodePoint(compBarr);
			Assert.AreEqual(p, decComp, "Error decoding compressed point");
		}

		/**
		 * Calls <code>implTestAddSubtract()</code>,
		 * <code>implTestMultiply</code> and <code>implTestEncoding</code> for
		 * the standard elliptic curves as given in <code>SecNamedCurves</code>.
		 */
		[Test]
		public void TestAddSubtractMultiplyTwiceEncoding()
		{
			foreach (string name in SecNamedCurves.Names)
			{
				X9ECParameters x9ECParameters = SecNamedCurves.GetByName(name);

				IBigInteger n = x9ECParameters.N;

				// The generator is multiplied by random b to get random q
				IBigInteger b = new BigInteger(n.BitLength, _secRand);
				ECPoint g = x9ECParameters.G;
				ECPoint q = g.Multiply(b);

				// Get point at infinity on the curve
				ECPoint infinity = x9ECParameters.Curve.Infinity;

				implTestAddSubtract(q, infinity);
				ImplTestMultiply(q, n.BitLength);
				ImplTestMultiply(infinity, n.BitLength);
				implTestEncoding(q);
			}
		}
	}
}