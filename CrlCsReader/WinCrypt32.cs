
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CrlCsReader
{
    internal static class WinCrypt32
    {


        [DllImport("CRYPT32.DLL", EntryPoint = "CryptQueryObject", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptQueryObject(
            Int32 dwObjectType,
            IntPtr pvObject,
            Int32 dwExpectedContentTypeFlags,
            Int32 dwExpectedFormatTypeFlags,
            Int32 dwFlags,
            IntPtr pdwMsgAndCertEncodingType,
            IntPtr pdwContentType,
            IntPtr pdwFormatType,
            ref IntPtr phCertStore,
            IntPtr phMsg,
            ref IntPtr ppvContext
            );

        [DllImport("CRYPT32.DLL", EntryPoint = "CertFreeCRLContext", SetLastError = true)]
        public static extern Boolean CertFreeCRLContext(
            IntPtr pCrlContext
        );

        [DllImport("CRYPT32.DLL", EntryPoint = "CertNameToStr", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertNameToStr(
            Int32 dwCertEncodingType,
            ref CRYPTOAPI_BLOB pName,
            Int32 dwStrType,
            StringBuilder psz,
            Int32 csz
        );

        [DllImport("CRYPT32.DLL", EntryPoint = "CertFindExtension", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertFindExtension(
            [MarshalAs(UnmanagedType.LPStr)]String pszObjId,
            Int32 cExtensions,
            IntPtr rgExtensions
        );

        [DllImport("CRYPT32.DLL", EntryPoint = "CryptFormatObject", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptFormatObject(
            Int32 dwCertEncodingType,
            Int32 dwFormatType,
            Int32 dwFormatStrType,
            IntPtr pFormatStruct,
            [MarshalAs(UnmanagedType.LPStr)]String lpszStructType,
            IntPtr pbEncoded,
            Int32 cbEncoded,
            StringBuilder pbFormat,
            ref Int32 pcbFormat
        );



        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_OBJID_BLOB
        {
            public uint cbData;
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)]
            public byte[] pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct CERT_PUBLIC_KEY_INFO
        {
            public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
            public CRYPTOAPI_BLOB PublicKey;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CERT_EXTENSION
        {
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszObjId;
            public bool fCritical;
            public CRYPTOAPI_BLOB Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_CONTEXT
        {
            public uint dwCertEncodingType;
            public IntPtr pbCertEncoded;
            public uint cbCertEncoded;
            public IntPtr pCertInfo;
            public IntPtr hCertStore;
        }

        public struct CERT_INFO
        {
            public int dwVersion;
            public CRYPTOAPI_BLOB SerialNumber;
            public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public CRYPTOAPI_BLOB Issuer;
            public FILETIME NotBefore;
            public FILETIME NotAfter;
            public CRYPTOAPI_BLOB Subject;
            public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
            public CRYPTOAPI_BLOB IssuerUniqueId;
            public CRYPTOAPI_BLOB SubjectUniqueId;
            public int cExtension;
            public CERT_EXTENSION rgExtension;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRL_CONTEXT
        {
            public Int32 dwCertEncodingType;
            public IntPtr pbCrlEncoded;
            public Int32 cbCrlEncoded;
            public IntPtr pCrlInfo;
            public IntPtr hCertStore;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRL_INFO
        {
            public Int32 dwVersion;
            public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public CRYPTOAPI_BLOB Issuer;
            public FILETIME ThisUpdate;
            public FILETIME NextUpdate;
            public Int32 cCRLEntry;
            public IntPtr rgCRLEntry;
            public Int32 cExtension;
            public IntPtr rgExtension;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPStr)]
            public String pszObjId;
            public CRYPTOAPI_BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPTOAPI_BLOB
        {
            public Int32 cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public Int32 dwLowDateTime;
            public Int32 dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRL_ENTRY
        {
            public CRYPTOAPI_BLOB SerialNumber;
            public FILETIME RevocationDate;
            public Int32 cExtension;
            public IntPtr rgExtension;
        }


        public const Int32 CERT_QUERY_OBJECT_FILE = 0x00000001;
        public const Int32 CERT_QUERY_OBJECT_BLOB = 0x00000002;
        public const Int32 CERT_QUERY_CONTENT_CRL = 3;
        public const Int32 CERT_QUERY_CONTENT_FLAG_CRL = 1 << CERT_QUERY_CONTENT_CRL;
        public const Int32 CERT_QUERY_FORMAT_BINARY = 1;
        public const Int32 CERT_QUERY_FORMAT_BASE64_ENCODED = 2;
        public const Int32 CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3;
        public const Int32 CERT_QUERY_FORMAT_FLAG_BINARY = 1 << CERT_QUERY_FORMAT_BINARY;
        public const Int32 CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = 1 << CERT_QUERY_FORMAT_BASE64_ENCODED;
        public const Int32 CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = 1 << CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED;
        public const Int32 CERT_QUERY_FORMAT_FLAG_ALL = CERT_QUERY_FORMAT_FLAG_BINARY | CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED | CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED;

        public const Int32 X509_ASN_ENCODING = 0x00000001;
        public const Int32 PKCS_7_ASN_ENCODING = 0x00010000;

        public const Int32 X509_NAME = 7;

        public const Int32 CERT_SIMPLE_NAME_STR = 1;
        public const Int32 CERT_OID_NAME_STR = 2;
        public const Int32 CERT_X500_NAME_STR = 3;

        public const String szOID_CRL_REASON_CODE = "2.5.29.21";

        public enum Disposition : uint
        {
            CERT_STORE_ADD_NEW = 1,
            CERT_STORE_ADD_USE_EXISTING = 2,
            CERT_STORE_ADD_REPLACE_EXISTING = 3,
            CERT_STORE_ADD_ALWAYS = 4,
            CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5,
            CERT_STORE_ADD_NEWER = 6,
            CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7,
        }

        [Flags]
        public enum FindFlags : int
        {
            CRL_FIND_ISSUED_BY_AKI_FLAG = 0x1,
            CRL_FIND_ISSUED_BY_SIGNATURE_FLAG = 0x2,
            CRL_FIND_ISSUED_BY_DELTA_FLAG = 0x4,
            CRL_FIND_ISSUED_BY_BASE_FLAG = 0x8,
        }

        public enum FindType : int
        {
            CRL_FIND_ANY = 0,
            CRL_FIND_ISSUED_BY = 1,
            CRL_FIND_EXISTING = 2,
            CRL_FIND_ISSUED_FOR = 3
        }

    }
}
