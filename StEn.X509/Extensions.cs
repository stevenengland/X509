namespace StEn.X509
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;

    /// <summary>
    /// Extensions to the X509Certificate2 Class.
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Sets the pin of a <see cref="X509Certificate2"/> to extract the private key.
        /// </summary>
        /// <param name="certificate">
        /// The certificate to set the pin for.
        /// </param>
        /// <param name="pin">
        /// The pin.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// Thrown if the certificate is null.
        /// </exception>
        /// <remarks>The PIN is remembered until the X509Certificate2 instance is open</remarks>
        public static void SetPinForPrivateKey(this X509Certificate2 certificate, string pin)
        {
            if (certificate == null)
                throw new ArgumentNullException("certificate");
            var key = (RSACryptoServiceProvider)certificate.PrivateKey;

            var providerHandle = IntPtr.Zero;
            var pinBuffer = Encoding.ASCII.GetBytes(pin);

            // provider handle is implicitly released when the certificate handle is released.
            SafeNativeMethods.Execute(
                () =>
                SafeNativeMethods.CryptAcquireContext(
                    ref providerHandle,
                    key.CspKeyContainerInfo.KeyContainerName,
                    key.CspKeyContainerInfo.ProviderName,
                key.CspKeyContainerInfo.ProviderType,
                    SafeNativeMethods.CryptContextFlags.Silent));
            SafeNativeMethods.Execute(
                () =>
                SafeNativeMethods.CryptSetProvParam(
                    providerHandle,
                    SafeNativeMethods.CryptParameter.KeyExchangePin,
                    pinBuffer,
                    0));
            SafeNativeMethods.Execute(
                () =>
                SafeNativeMethods.CertSetCertificateContextProperty(
                    certificate.Handle,
                    SafeNativeMethods.CertificateProperty.CryptoProviderHandle,
                    0,
                    providerHandle));
        }
    }
}
