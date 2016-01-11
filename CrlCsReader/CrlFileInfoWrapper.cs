using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;

namespace CrlCsReader
{
    public class CrlFileInfoWrapper
    {
        private List<string> _revokedSerialNumbers;
        private DateTime _validFrom;
        private DateTime _validUntil;

        public List<string> RevokedSerialNumbers { get { return _revokedSerialNumbers; } }
        public DateTime EffectiveDate { get { return _validFrom; } }
        public DateTime NextUpdate { get { return _validUntil; } }

        public CrlFileInfoWrapper()
        {

        }
        public CrlFileInfoWrapper(byte[] crlFileBinary)
        {
            PopulateCrlWrapperFields(crlFileBinary);
        }
        public void PopulateCrlWrapperFields(byte[] CrlFileBinary)
        {
            var phCertStore = IntPtr.Zero;
            var pvContext = IntPtr.Zero;
            var hCrlData = new GCHandle();
            var hCryptBlob = new GCHandle();
            try
            {
                hCrlData = GCHandle.Alloc(CrlFileBinary, GCHandleType.Pinned);
                WinCrypt32.CRYPTOAPI_BLOB stCryptBlob;
                stCryptBlob.cbData = CrlFileBinary.Length;
                stCryptBlob.pbData = hCrlData.AddrOfPinnedObject();
                hCryptBlob = GCHandle.Alloc(stCryptBlob, GCHandleType.Pinned);

                if (!WinCrypt32.CryptQueryObject(
                WinCrypt32.CERT_QUERY_OBJECT_BLOB,
                hCryptBlob.AddrOfPinnedObject(),
                WinCrypt32.CERT_QUERY_CONTENT_FLAG_CRL,
                WinCrypt32.CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                ref phCertStore,
                IntPtr.Zero,
                ref pvContext
                ))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CRL is Corrupted.");
                }

                var stCrlContext = (WinCrypt32.CRL_CONTEXT)Marshal.PtrToStructure(pvContext, typeof(WinCrypt32.CRL_CONTEXT));
                var stCrlInfo = (WinCrypt32.CRL_INFO)Marshal.PtrToStructure(stCrlContext.pCrlInfo, typeof(WinCrypt32.CRL_INFO));

                _validUntil = ReadFromFileTime(stCrlInfo.NextUpdate);
                _validFrom = ReadFromFileTime(stCrlInfo.ThisUpdate);
                PopulateRevokedSerialNumbers(stCrlInfo);

            }
            finally
            {
                if (hCrlData.IsAllocated) hCrlData.Free();
                if (hCryptBlob.IsAllocated) hCryptBlob.Free();
                if (!pvContext.Equals(IntPtr.Zero))
                {
                    WinCrypt32.CertFreeCRLContext(pvContext);
                }
            }
        }

        private DateTime ReadFromFileTime(WinCrypt32.FILETIME fileTime)
        {
            var uhigh = (ulong)fileTime.dwHighDateTime;
            var ulow = (uint)fileTime.dwLowDateTime;
            uhigh = uhigh << 32;
            var ticks = (long)(uhigh | ulow);
            return DateTime.FromFileTimeUtc(ticks);
        }

        private void PopulateRevokedSerialNumbers(WinCrypt32.CRL_INFO stCrlInfo)
        {
            _revokedSerialNumbers = new List<string>();
            var rgCrlEntry = stCrlInfo.rgCRLEntry;

            for (var i = 0; i < stCrlInfo.cCRLEntry; i++)
            {
                var serial = string.Empty;
               var stCrlEntry = (WinCrypt32.CRL_ENTRY)Marshal.PtrToStructure(rgCrlEntry, typeof(WinCrypt32.CRL_ENTRY));

                IntPtr pByte = stCrlEntry.SerialNumber.pbData;
                for (var j = 0; j < stCrlEntry.SerialNumber.cbData; j++)
                {
                    Byte bByte = Marshal.ReadByte(pByte);
                    serial = bByte.ToString("X").PadLeft(2, '0') + serial;
                    pByte = pByte + Marshal.SizeOf(typeof(byte));

                }
                _revokedSerialNumbers.Add(serial);
                rgCrlEntry = rgCrlEntry + Marshal.SizeOf(typeof(WinCrypt32.CRL_ENTRY));
            }
        }
    }
}
