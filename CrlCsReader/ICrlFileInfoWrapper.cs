using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CrlCsReader
{
    public interface ICrlFileInfoWrapper
    {
        List<string> RevokedSerialNumbers { get; }
        DateTime EffectiveDate { get; }
        DateTime NextUpdate { get; }

        void PopulateCrlWrapperFields(byte[] crlFileBinary);
    }
}
