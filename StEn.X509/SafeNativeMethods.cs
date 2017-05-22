namespace StEn.X509
{
    using System;
    using System.ComponentModel;
    using System.Runtime.InteropServices;

    /// <summary>
    /// Provides access to native methods.
    /// </summary>
    internal static class SafeNativeMethods
    {
        /// <summary>
        /// The crypt context flags.
        /// </summary>
        internal enum CryptContextFlags
        {
            /// <summary>
            /// No Context.
            /// </summary>
            None = 0,

            /// <summary>
            /// Silent context.
            /// </summary>
            Silent = 0x40
        }

        /// <summary>
        /// The certificate property.
        /// </summary>
        internal enum CertificateProperty
        {
            /// <summary>
            /// No Property.
            /// </summary>
            None = 0,

            /// <summary>
            /// Crypto provider handle.
            /// </summary>
            CryptoProviderHandle = 0x1
        }

        /// <summary>
        /// The crypt parameter.
        /// </summary>
        internal enum CryptParameter
        {
            /// <summary>
            /// No Parameter.
            /// </summary>
            None = 0,

            /// <summary>
            /// Key exchange pin.
            /// </summary>
            KeyExchangePin = 0x20
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptAcquireContext(
            ref IntPtr hProv,
            string containerName,
            string providerName,
            int providerType,
            CryptContextFlags flags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CryptSetProvParam(
            IntPtr hProv,
            CryptParameter dwParam,
            [In] byte[] pbData,
            uint dwFlags);

        [DllImport("CRYPT32.DLL", SetLastError = true)]
        internal static extern bool CertSetCertificateContextProperty(
            IntPtr pCertContext,
            CertificateProperty propertyId,
            uint dwFlags,
            IntPtr pvData);

        /// <summary>
        /// Executes a native method.
        /// </summary>
        /// <param name="action">
        /// The action to execute.
        /// </param>
        /// <exception cref="Win32Exception">
        /// Thrown if the native call fails.
        /// </exception>
        internal static void Execute(Func<bool> action)
        {
            if (!action())
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}