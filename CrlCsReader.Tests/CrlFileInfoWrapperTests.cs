using System;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CrlCsReader.Tests
{
    [TestClass]
    public class CrlFileInfoWrapperTests
    {
        private const string crlBase64 = "MIIBnDCBiQIBATAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB2Zvby5iYXIXDTE2MDExMTAyMTg1NFoXDTM5MTIzMTIzNTk1OVqgRzBFMEMGA1UdAQQ8MDqAEFn/rGO+qzcEswGdCPleY4mhFDASMRAwDgYDVQQDEwdmb28uYmFyghBf8Z6E+BcohkYMjBnkktUUMAkGBSsOAwIdBQADggEBABKqjmyJ86rgn8+AT1x8ImGzUvCnK6ew3ZvYBb2xef/JcNA2U7watVwxIirmRatO7S25v9eO3IIHvoV/WdcPsQ0djKB6GJtoO+Qda3ua73r+zgj5jeGBTsV35cz+E6tvBdRJFsuPw13hmUX2oGZAfCQyvcoKlR3VD6TZy317Ekhhr2VE5dqZ5c/rzuvF6ldV9V/yxsVJRce87vnGJjEQh1pE2oHuAslyrb9i1+3A+6LLqhnUve4+RRJ4MQfLrHIbJ+qY+Ybies9DDotYYCzANiyfddetbNiPs7zHgMbshItIq09HtsF/uyml+J/KKPww+kFKcNINH1Nf6VNAzyIXTQk=";

        [TestMethod]
        public void CrlFileInfoWrapper_ReadsProperties()
        {
            var crlFile = Convert.FromBase64String(crlBase64);
            var sut = new CrlFileInfoWrapper(crlFile);

            Assert.AreEqual(0, sut.RevokedSerialNumbers.Count);  //Could not create a CRL with actual serials, but you do have one, you can test it here.
            Assert.AreEqual(new DateTime(2016,1,11,2,18,54), sut.EffectiveDate);
            Assert.AreEqual(new DateTime(2039, 12,31,23,59,59) ,sut.NextUpdate);
        }
    }
}
