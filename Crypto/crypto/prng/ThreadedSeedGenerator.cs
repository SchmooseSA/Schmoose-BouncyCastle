using System;
using System.Threading;
using Org.BouncyCastle.Utilities;

#if NETFX_CORE
using Windows.System.Threading;
#endif

namespace Org.BouncyCastle.Crypto.Prng
{
    /**
     * A thread based seed generator - one source of randomness.
     * <p>
     * Based on an idea from Marcus Lippert.
     * </p>
     */
    public class ThreadedSeedGenerator
    {
        private class SeedGenerator
        {
#if NETCF_1_0
			// No volatile keyword, but all fields implicitly volatile anyway
			private int		counter = 0;
			private bool	stop = false;
#else
            private volatile int _counter;
            private volatile bool _stop;
#endif

            private void Run(object ignored)
            {
                while (!_stop)
                {
                    _counter++;
                }
            }

            public byte[] GenerateSeed(int numBytes, bool fast)
            {
                _counter = 0;
                _stop = false;

                var result = new byte[numBytes];
                var last = 0;
                var end = fast ? numBytes : numBytes * 8;

#if NETFX_CORE
                var task = ThreadPool.RunAsync(this.Run);

#else
				ThreadPool.QueueUserWorkItem(Run);
#endif
                for (int i = 0; i < end; i++)
                {
                    while (this._counter == last)
                    {
                        try
                        {
                            Platform.ThreadSleep(1);
                        }
                        catch (Exception)
                        {
                            // ignore
                        }
                    }

                    last = _counter;

                    if (fast)
                    {
                        result[i] = (byte)last;
                    }
                    else
                    {
                        var bytepos = i / 8;
                        result[bytepos] = (byte)((result[bytepos] << 1) | (last & 1));
                    }
                }

                _stop = true;
#if NETFX_CORE
                task.Cancel();
#endif
                return result;
            }
        }

        /**
         * Generate seed bytes. Set fast to false for best quality.
         * <p>
         * If fast is set to true, the code should be round about 8 times faster when
         * generating a long sequence of random bytes. 20 bytes of random values using
         * the fast mode take less than half a second on a Nokia e70. If fast is set to false,
         * it takes round about 2500 ms.
         * </p>
         * @param numBytes the number of bytes to generate
         * @param fast true if fast mode should be used
         */
        public byte[] GenerateSeed(
            int numBytes,
            bool fast)
        {
            return new SeedGenerator().GenerateSeed(numBytes, fast);
        }
    }
}
