using System;

namespace Org.BouncyCastle.Bcpg.Attr
{
    public class ExperimentalAttribute : UserAttributeSubpacket
    {
        public ExperimentalAttribute(UserAttributeSubpacketTag tag, byte[] data)
            : base(tag, data)
        {
            if(tag < UserAttributeSubpacketTag.Experimental_1 || tag > UserAttributeSubpacketTag.Experimental_11)
                throw new ArgumentException("tag must be one of the experimental tags.", "tag");
        }
    }
}
