Schmoose-BouncyCastle
=====================

This clone of [Bouncy Castle][1] was original created from [neoeinstein][2] to add Silverlight and WindowsPhone support.
From here, we added projects for Xamarin MonoDroid, PCL and WinRT.

What has changed?
-----------------
* Deviding Interfaces and Implementation
* Code cleanup and refactoring
* Use of Generics (more to do)

What has improved?
------------------
* Full support of [RFC 6673][3]
* Accessive use of `using(...)` pattern to assure streams and `IDisposables` are closed and released as soon as possible

[1]: http://www.bouncycastle.org/csharp/
[2]: https://github.com/neoeinstein/bouncycastle
[3]: http://tools.ietf.org/html/rfc6637