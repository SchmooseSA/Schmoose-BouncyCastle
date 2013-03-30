using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement.Srp
{
	/**
	 * Implements the client side SRP-6a protocol. Note that this class is stateful, and therefore NOT threadsafe.
	 * This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
	 * "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
	 */
	public class Srp6Client
	{
	    protected IBigInteger N;
	    protected IBigInteger g;

	    protected IBigInteger privA;
	    protected IBigInteger pubA;

	    protected IBigInteger B;

	    protected IBigInteger x;
	    protected IBigInteger u;
	    protected IBigInteger S;

	    protected IDigest digest;
	    protected SecureRandom random;

	    public Srp6Client()
	    {
	    }

	    /**
	     * Initialises the client to begin new authentication attempt
	     * @param N The safe prime associated with the client's verifier
	     * @param g The group parameter associated with the client's verifier
	     * @param digest The digest algorithm associated with the client's verifier
	     * @param random For key generation
	     */
	    public virtual void Init(IBigInteger N, IBigInteger g, IDigest digest, SecureRandom random)
	    {
	        this.N = N;
	        this.g = g;
	        this.digest = digest;
	        this.random = random;
	    }

	    /**
	     * Generates client's credentials given the client's salt, identity and password
	     * @param salt The salt used in the client's verifier.
	     * @param identity The user's identity (eg. username)
	     * @param password The user's password
	     * @return Client's public value to send to server
	     */
	    public virtual IBigInteger GenerateClientCredentials(byte[] salt, byte[] identity, byte[] password)
	    {
	        this.x = Srp6Utilities.CalculateX(digest, N, salt, identity, password);
	        this.privA = SelectPrivateValue();
	        this.pubA = g.ModPow(privA, N);

	        return pubA;
	    }

	    /**
	     * Generates client's verification message given the server's credentials
	     * @param serverB The server's credentials
	     * @return Client's verification message for the server
	     * @throws CryptoException If server's credentials are invalid
	     */
	    public virtual IBigInteger CalculateSecret(IBigInteger serverB)
	    {
	        this.B = Srp6Utilities.ValidatePublicValue(N, serverB);
	        this.u = Srp6Utilities.CalculateU(digest, N, pubA, B);
	        this.S = CalculateS();

	        return S;
	    }

	    protected virtual IBigInteger SelectPrivateValue()
	    {
	    	return Srp6Utilities.GeneratePrivateValue(digest, N, g, random);    	
	    }

	    private IBigInteger CalculateS()
	    {
	        IBigInteger k = Srp6Utilities.CalculateK(digest, N, g);
	        IBigInteger exp = u.Multiply(x).Add(privA);
	        IBigInteger tmp = g.ModPow(x, N).Multiply(k).Mod(N);
	        return B.Subtract(tmp).Mod(N).ModPow(exp, N);
	    }
	}
}
