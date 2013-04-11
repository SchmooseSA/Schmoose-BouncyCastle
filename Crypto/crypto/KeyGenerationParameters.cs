using System;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    /**
     * The base class for parameters to key generators.
     */
    public class KeyGenerationParameters : IKeyGenerationParameters
    {
        private readonly ISecureRandom _random;
        private readonly int _strength;

        /**
         * initialise the generator with a source of randomness
         * and a strength (in bits).
         *
         * @param random the random byte source.
         * @param strength the size, in bits, of the keys we want to produce.
         */
        public KeyGenerationParameters(ISecureRandom random, int strength)
        {
            if (random == null)
                throw new ArgumentNullException("random");
            if (strength < 1)
                throw new ArgumentException("strength must be a positive value", "strength");

            _random = random;
            _strength = strength;
        }

        /**
         * return the random source associated with this
         * generator.
         *
         * @return the generators random source.
         */
        public ISecureRandom Random
        {
            get { return _random; }
        }

        /**
         * return the bit strength for keys produced by this generator,
         *
         * @return the strength of the keys this generator produces (in bits).
         */
        public int Strength
        {
            get { return _strength; }
        }
    }
}
