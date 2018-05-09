using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace mobile_ca
{
    /// <summary>
    /// Provides functions to handle Certificate and Certificate Store interaction
    /// </summary>
    public static class CertStore
    {
        /// <summary>
        /// OID for the SAN Entry of a Certificate
        /// </summary>
        public const string OID_SAN = "2.5.29.17";

        /// <summary>
        /// Gets the Thumbprint of the certificate that signed another
        /// </summary>
        /// <param name="CertContent">Certificate to check signer of</param>
        /// <param name="CAContent">List of possible signers</param>
        /// <returns>Thumbprint of signer, null if not found</returns>
        public static string GetSignerCertHash(string CertContent, string[] CAContent)
        {
            var CAs = CAContent.Select(m => GetCert(m)).ToArray();
            var Cert = GetCert(CertContent);
            if (CAs.All(m => m != null) && Cert != null)
            {
                X509Chain chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.VerificationFlags =
                    //Allow our own CA
                    X509VerificationFlags.AllowUnknownCertificateAuthority |
                    //Don't care if one of the certs has expired
                    X509VerificationFlags.IgnoreNotTimeValid |
                    //Don't care if the client cert validity is outside of the root cert
                    X509VerificationFlags.IgnoreNotTimeNested;
                chain.ChainPolicy.VerificationTime = DateTime.Now;
                chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 0);

                chain.ChainPolicy.ExtraStore.AddRange(CAs);

                if (!chain.Build(Cert))
                {
                    string[] errors = chain.ChainStatus
                        .Select(x => string.Format("{0} ({1})", x.StatusInformation.Trim(), x.Status))
                        .ToArray();
                    string certificateErrorsString = "Unknown errors.";

                    if (errors != null && errors.Length > 0)
                    {
                        certificateErrorsString = string.Join(", ", errors);
                    }
                    Logger.Error("Unable to construct Certificate Chain. Error: {0}", certificateErrorsString);
                }
                else
                {
                    if (chain.ChainElements.Count > 1)
                    {
                        var T = chain.ChainElements[chain.ChainElements.Count - 1].Certificate.Thumbprint;
                        if (CAs.Any(m => m.Thumbprint == T))
                        {
                            Logger.Debug("Thumbprint found: {0}", T);
                            chain.Reset();
                            return T;
                        }
                        else
                        {
                            Logger.Warn("Chain completed by a CA certificate from the system, not our own");
                        }
                    }
                }
                Logger.Warn("Attempted to find CA but none was available. Maybe it was deleted");
                chain.Reset();
            }
            return null;
        }

        /// <summary>
        /// Gets the SAN Entries of a certificate
        /// </summary>
        /// <param name="CertContent">Certificate</param>
        /// <returns>SAN entries. Null if none found</returns>
        public static string[] GetSan(string CertContent)
        {
            var Cert = GetCert(CertContent);
            if (Cert != null)
            {
                var SAN = Cert.Extensions.OfType<X509Extension>().FirstOrDefault(m => m.Oid.Value == OID_SAN);
                if (SAN != null)
                {
                    Logger.Debug("GETSAN: {0}", SAN.Format(false));
                    return SAN.Format(true).Split('\n')
                        .Select(m => m.Trim().Split('=').Last())
                        .Where(m => !string.IsNullOrEmpty(m))
                        .ToArray();
                }
                else
                {
                    Logger.Debug("No SAN");
                }
            }
            return null;
        }

        /// <summary>
        /// Gets the Thumbprint of a certificate
        /// </summary>
        /// <param name="CertContent">Certificate</param>
        /// <returns>Thumbprint. Null on error</returns>
        public static string GetThumb(string CertContent)
        {
            Logger.Debug("Reading thumbprint from Certificate");
            var Cert = GetCert(CertContent);
            if (Cert != null)
            {
                try
                {
                    return Cert.Thumbprint;
                }
                catch (Exception ex)
                {
                    Logger.Error("Unable to get thumbprint. Reason: {0}", ex.Message);
                }
            }
            return null;
        }

        public static bool IsSHA1(string parent)
        {
            if (!string.IsNullOrEmpty(parent))
            {
                var R = new Regex(@"^[\da-fA-F]{40}$");
                return R.IsMatch(parent);
            }
            return false;
        }

        /// <summary>
        /// Gets the Name of a certificate
        /// </summary>
        /// <param name="CertContent">Certificate</param>
        /// <returns>Name</returns>
        public static string GetName(string CertContent)
        {
            var Cert = GetCert(CertContent);
            if (Cert != null)
            {
                if (string.IsNullOrEmpty(Cert.FriendlyName))
                {
                    return Cert.GetNameInfo(X509NameType.SimpleName, false);
                }
                return Cert.FriendlyName;
            }
            return null;
        }

        /// <summary>
        /// Installs a root certificate
        /// </summary>
        /// <param name="CertContent">Certificate</param>
        /// <param name="UseMachineStore">true to use machine store instead of user store</param>
        /// <returns>true if installed</returns>
        /// <remarks>Windows will always prompt the user for installing</remarks>
        public static bool InstallRoot(string CertContent, bool UseMachineStore = false)
        {
            var Cert = GetCert(CertContent);
            if (Cert != null)
            {
                var Ret = true;
                Logger.Debug("Installing Cert {0}", Cert.Thumbprint);
                Cert.FriendlyName = Cert.GetNameInfo(X509NameType.SimpleName, false);
                X509Store store = new X509Store(StoreName.Root, UseMachineStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                try
                {
                    store.Add(Cert);
                    Logger.Log("Certificate installed");
                }
                catch (Exception ex)
                {
                    Logger.Error("Unable to add Root CA. Reason: {0}", ex.Message);
                    Ret = false;
                }
                store.Close();
                return Ret;
            }
            return false;
        }

        /// <summary>
        /// Checks if the given certificate hash has been installed
        /// </summary>
        /// <param name="Hash">Certificate Thumbprint</param>
        /// <param name="UseMachineStore">true to use machine store instead of user store</param>
        /// <returns>true if this certificate is installed</returns>
        public static bool HasCert(string Hash, bool UseMachineStore = false)
        {
            if (Hash != null)
            {
                Logger.Debug("Checking if {0} is installed", Hash);
                return GetAllRootHashes().Any(m => m.ToLower() == Hash.ToLower());
            }
            else
            {
                Logger.Error("Attempted to pass Hash=null into HasCert");
            }
            return false;
        }

        /// <summary>
        /// Gets all Thumbprints from the root store
        /// </summary>
        /// <param name="UseMachineStore">true to use machine store instead of user store</param>
        /// <returns>List of Thumbprints</returns>
        public static string[] GetAllRootHashes(bool UseMachineStore = false)
        {
            Logger.Debug("Loading all Root Hashes");
            return GetAllRootCertificates(UseMachineStore).Select(m => GetThumb(m)).ToArray();
        }

        /// <summary>
        /// Retrieves all root certificates from the current machine store
        /// </summary>
        /// <param name="UseMachineStore">true to use machine store instead of user store</param>
        /// <returns>List of certificates</returns>
        public static string[] GetAllRootCertificates(bool UseMachineStore = false)
        {
            Logger.Debug("Loading all Root Certificates");
            X509Store store = new X509Store(StoreName.Root, UseMachineStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            var Result = store.Certificates.OfType<X509Certificate2>().Select(m =>
                "-----BEGIN CERTIFICATE-----\r\n" +
                Convert.ToBase64String(m.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks) +
                "\r\n-----END CERTIFICATE-----").ToArray();
            store.Close();
            return Result;
        }

        /// <summary>
        /// Removes a root certificate from the certificate store
        /// </summary>
        /// <param name="Hash">Certificate Thumbprint</param>
        /// <param name="UseMachineStore">true to use machine store instead of user store</param>
        /// <returns>Number of certificates removed</returns>
        /// <remarks>Windows will always prompt the user for installing</remarks>
        public static int RemoveRoot(string Hash, bool UseMachineStore = false)
        {
            var Removed = 0;
            X509Store store = new X509Store(StoreName.Root, UseMachineStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            var Certs = store.Certificates.Find(X509FindType.FindByThumbprint, Hash, false);
            if (Certs != null && Certs.Count > 0)
            {
                foreach (var Cert in Certs)
                {
                    Logger.Debug("Removing cert {0}", Cert.Thumbprint);
                    try
                    {
                        store.Remove(Cert);
                        ++Removed;
                    }
                    catch (Exception ex)
                    {
                        Logger.Error("Unable to remove {0} from store. Reason: {1}", Hash, ex.Message);
                    }
                }
            }
            else
            {
                Logger.Warn("Attempt to remove non-existant Certificate");
            }
            store.Close();
            return Removed;
        }

        /// <summary>
        /// Converts a string into a Certificate
        /// </summary>
        /// <param name="CertContent">PEM formatted certificate content</param>
        /// <returns>Certificate, null on error</returns>
        public static X509Certificate2 GetCert(string CertContent)
        {
            try
            {
                return new X509Certificate2(Encoding.ASCII.GetBytes(CertContent));
            }
            catch (Exception ex)
            {
                Logger.Error("Unable to create Certificate from string. Reason: {0}", ex.Message);
            }
            return null;
        }
    }
}
