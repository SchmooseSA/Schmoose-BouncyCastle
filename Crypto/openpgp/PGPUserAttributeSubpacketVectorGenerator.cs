using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Bcpg.Attr;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpUserAttributeSubpacketVectorGenerator
    {
        private readonly IList<IUserAttributeSubpacket> _list = Platform.CreateArrayList<IUserAttributeSubpacket>();

        public virtual void SetImageAttribute(ImageAttribute.Format imageType, byte[] imageData)
        {
            if (imageData == null)
                throw new ArgumentException(@"attempt to set null image", "imageData");

            _list.Add(new ImageAttribute(imageType, imageData));
        }

        public virtual void AddSubPacket(IUserAttributeSubpacket subpacket)
        {
            if (subpacket == null)
                throw new ArgumentNullException("subpacket", "attempt to add null packet");
            _list.Add(subpacket);
        }

        public virtual PgpUserAttributeSubpacketVector Generate()
        {
            return new PgpUserAttributeSubpacketVector(_list.ToArray());
        }
    }
}
