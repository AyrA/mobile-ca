#if DEBUG
#define LOG_STDERR
#endif
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;

namespace mobile_ca
{
    /// <summary>
    /// Provides Tools for Certificate handling with openssl
    /// </summary>
    public static class CertCommands
    {
#if DEBUG
        /// <summary>
        /// Command for OpenSSL
        /// </summary>
        public const string OPENSSL_COMMAND = @"C:\OpenSSL-Win32\bin\openssl.exe";
#else
        /// <summary>
        /// Command for OpenSSL
        /// </summary>
        public const string OPENSSL_COMMAND = @"openssl.exe";
#endif

        /// <summary>
        /// Valid RSA Key sizes.
        /// </summary>
        /// <remarks>
        /// Don't add numbers lower than 1024, These certs will not work with Windows.
        /// 512 does technically works but Windows considers the cert to be tampered with.
        /// 8192 has been confirmed to work under Windows 7
        /// </remarks>
        public static readonly int[] ValidKeySizes = { 1024, 2048, 4096, 8192 };

        /// <summary>
        /// List of required OpenSSL binaries and where to obtain them
        /// </summary>
        private static readonly Dictionary<string, string> OpenSSLBinaries = new Dictionary<string, string>()
        {
            {"https://master.ayra.ch/LOGIN/pub/applications/Tools/OpenSSL/openssl.exe" ,"openssl.exe" },
            {"https://master.ayra.ch/LOGIN/pub/applications/Tools/OpenSSL/libeay32.dll","libeay32.dll"},
            {"https://master.ayra.ch/LOGIN/pub/applications/Tools/OpenSSL/ssleay32.dll","ssleay32.dll"}
        };

        /// <summary>
        /// Simple OpenSSL Validation
        /// </summary>
        /// <returns>true if openssl available and answering</returns>
        public static bool ValidateOpenSSL(bool CheckVersion = false)
        {
            var FullPath = Path.GetDirectoryName(Path.Combine(Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), OPENSSL_COMMAND));
            if (File.Exists(Path.Combine(FullPath, OPENSSL_COMMAND)) &&
                File.Exists(Path.Combine(FullPath, "libeay32.dll")) &&
                File.Exists(Path.Combine(FullPath, "ssleay32.dll")))
            {
                if (CheckVersion && string.IsNullOrEmpty(Version()))
                {
                    Logger.Error("The command 'openssl.exe version' did not work as expected. Invalid binaries?");
                    return false;
                }
                return true;
            }
            return false;
        }

        /// <summary>
        /// Downloads a copy of the required OpenSSL binaries
        /// </summary>
        /// <param name="Destination">Destination Directory</param>
        /// <returns>true if successfull</returns>
        public static bool Obtain(string Destination = "<proc>", bool Overwrite = false)
        {
            var Base = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(Destination == "<proc>" ? Process.GetCurrentProcess().MainModule.FileName : Destination)), "Data");
            foreach (var Entry in OpenSSLBinaries)
            {
                var Dest = Path.Combine(Base, Entry.Value);
                if (Overwrite || !File.Exists(Dest))
                {
                    Logger.Log("Downloading {0}", Entry.Value);
                    using (var WC = new WebClient())
                    {
                        try
                        {
                            WC.DownloadFile(Entry.Key, Dest);
                        }
                        catch (Exception ex)
                        {
                            Logger.Error("Unable to download {0} from {1}. Reason: {2}", Entry.Value, Entry.Key, ex.Message);
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        /// <summary>
        /// Obtains current Version number of OpenSSL
        /// </summary>
        /// <returns>OpenSSL Version</returns>
        public static string Version()
        {
            return Run("version");
        }

        /// <summary>
        /// Tests if the given Number is a valid Key Size
        /// </summary>
        /// <param name="Size">Key Size</param>
        /// <returns>true for valid sizes</returns>
        public static bool IsValidKeySize(int Size)
        {
            return Size > 0 && ValidKeySizes.Contains(Size);
        }

        /// <summary>
        /// Generates an RSA Key
        /// </summary>
        /// <param name="Size">Key Size</param>
        /// <returns>RSA Key</returns>
        public static string GenerateKey(int Size)
        {
            Logger.Log("Generating RSA Key with {0} bits", Size);
            if (IsValidKeySize(Size))
            {
                var Key = Run("genrsa", Size);
                Logger.Debug("RSA Key:\n{0}", Key);
                return Key;
            }
            else
            {
                Logger.Error("Invalid Key Size");
            }
            throw new ArgumentException("invalid KeySize");
        }

        /// <summary>
        /// Generates a new Root Certificate
        /// </summary>
        /// <param name="PrivateKey">Private key content</param>
        /// <param name="ExpirationDays">Expiration in days</param>
        /// <param name="UseSha256">Use SHA256 instead of SHA1</param>
        /// <param name="CountryCode">Two-letter ISO Country code</param>
        /// <param name="State">State</param>
        /// <param name="Town">Town</param>
        /// <param name="Organization">Company Name</param>
        /// <param name="OrganizationUnit">Department</param>
        /// <param name="CommonName">Display Name for Certificate</param>
        /// <param name="EmailAddress">E-Mail address for Certificate</param>
        /// <returns>Certificate</returns>
        public static string GenerateRootCert(string PrivateKey, int ExpirationDays = 3650, bool UseSha256 = true, string CountryCode = "XX", string State = "Local", string Town = "Local", string Organization = "ACME", string OrganizationUnit = "ACME", string CommonName = "ACME Root CA", string EmailAddress = "ACME@example.com")
        {
            Logger.Log("Generating Root CA");
            if (string.IsNullOrEmpty(PrivateKey))
            {
                Logger.Error("PrivateKey not specified");
                throw new ArgumentNullException(nameof(PrivateKey));
            }
            if (ExpirationDays < 1)
            {
                Logger.Error("ExpirationDays too small");
                throw new ArgumentOutOfRangeException("ExpirationDays");
            }

            var Params = new Dictionary<string, string>();
            Params[nameof(CountryCode)] = CountryCode;
            Params[nameof(State)] = State;
            Params[nameof(Town)] = Town;
            Params[nameof(Organization)] = Organization;
            Params[nameof(OrganizationUnit)] = OrganizationUnit;
            Params[nameof(CommonName)] = CommonName;
            Params[nameof(EmailAddress)] = EmailAddress;
            foreach (var Entry in Params)
            {
                if (string.IsNullOrEmpty(Entry.Value))
                {
                    Logger.Error("{0} not specified", Entry.Key);
                    throw new ArgumentNullException(Entry.Key);
                }
                if (Entry.Value.Contains("/") || Entry.Value.Contains("\""))
                {
                    Logger.Error("{0} has invalid characters", Entry.Key);
                    throw new FormatException($"{Entry.Key} can't have slash or quote in it.");
                }
            }
            if (CountryCode.Length != 2)
            {
                Logger.Error("CountryCode not two chars in length");
                throw new FormatException("Country code must be 2 letter code");
            }
            Logger.Debug("Arguments OK");
            string Subject = $"/C={CountryCode}/ST={State}/L={Town}/O={Organization}/OU={OrganizationUnit}/CN={CommonName}/emailAddress={EmailAddress}";

            using (var TempKeyFile = new KillHandle())
            {
                Logger.Debug("Using {0} as temporary CA file", TempKeyFile.FileName);
                TempKeyFile.WriteAllText(PrivateKey);

                var RunParams = new string[]
                {
                    "req",
                    "-new",
                    "-x509",
                    //"-nodes",
                    UseSha256 ? "-sha256" : "-sha1",
                    "-key",
                    TempKeyFile.FileName,
                    "-days",
                    ExpirationDays.ToString(),
                    "-subj",
                    Subject,
                    "-extensions",
                    "v3_ca"
                };
                var CACert = Run(RunParams);
                Logger.Debug("CA Cert:\n{0},", CACert);
                return CACert;
            }
        }

        /// <summary>
        /// Generates a new Certificate
        /// </summary>
        /// <param name="RootKey">Root CA RSA Key</param>
        /// <param name="CaCert">Root CA Content</param>
        /// <param name="PrivateKey">Private RSA Key</param>
        /// <param name="HostName">HostName (often known as Common Name)</param>
        /// <param name="SAN">Alternative Host names</param>
        /// <param name="ExpirationDays">Expiration in days</param>
        /// <param name="UseSha256">Use SHA256 instead of SHA1</param>
        /// <param name="CountryCode">Two-letter ISO Country code</param>
        /// <param name="State">State</param>
        /// <param name="Town">Town</param>
        /// <param name="Organization">Company Name</param>
        /// <param name="OrganizationUnit">Department</param>
        /// <param name="EmailAddress">E-Mail address for Certificate</param>
        /// <returns>Certificate</returns>
        public static string GenerateCertificate(string RootKey, string CaCert, string PrivateKey, string HostName, string[] SAN = null, int ExpirationDays = 3650, bool UseSha256 = true, string CountryCode = "XX", string State = "Local", string Town = "Local", string Organization = "ACME", string OrganizationUnit = "ACME", string EmailAddress = "ACME@example.com")
        {
            Logger.Log("Generating Certificate");
            if (string.IsNullOrEmpty(HostName))
            {
                Logger.Error("HostName not specified");
                throw new ArgumentNullException(nameof(HostName));
            }
            if (string.IsNullOrEmpty(RootKey))
            {
                Logger.Error("RootKey not specified");
                throw new ArgumentNullException(nameof(RootKey));
            }
            if (string.IsNullOrEmpty(PrivateKey))
            {
                Logger.Error("PrivateKey not specified");
                throw new ArgumentNullException(nameof(PrivateKey));
            }
            if (ExpirationDays < 1)
            {
                Logger.Error("ExpirationDays too small");
                throw new ArgumentOutOfRangeException("ExpirationDays");
            }
            if (!Tools.IsValidIp(HostName) && !Tools.IsValidDomainName(HostName))
            {
                Logger.Error("HostName is invalid domain name or IP");
                throw new FormatException("HostName is invalid domain name or IP");
            }

            if (SAN != null && !SAN.All(m => Tools.IsValidDomainName(m) || Tools.IsValidIp(m)))
            {
                throw new FormatException("SAN contains invalid domain name or IP");
            }
            if (SAN == null || SAN.Length == 0)
            {
                SAN = new string[] { HostName };
            }

            var Params = new Dictionary<string, string>();
            Params[nameof(CountryCode)] = CountryCode;
            Params[nameof(State)] = State;
            Params[nameof(Town)] = Town;
            Params[nameof(Organization)] = Organization;
            Params[nameof(OrganizationUnit)] = OrganizationUnit;
            Params[nameof(HostName)] = HostName;
            Params[nameof(EmailAddress)] = EmailAddress;
            foreach (var Entry in Params)
            {
                if (string.IsNullOrEmpty(Entry.Value))
                {
                    Logger.Error("{0} not specified", Entry.Key);
                    throw new ArgumentNullException(Entry.Key);
                }
                if (Entry.Value.Contains("/") || Entry.Value.Contains("\""))
                {
                    Logger.Error("{0} has invalid characters", Entry.Key);
                    throw new FormatException($"{Entry.Key} can't have slash or quote in it.");
                }
            }
            if (CountryCode.Length != 2)
            {
                Logger.Error("CountryCode not two chars in length");
                throw new FormatException("Country code must be 2 letter code");
            }
            Logger.Debug("Arguments OK");
            string Subject = $"/C={CountryCode}/ST={State}/L={Town}/O={Organization}/OU={OrganizationUnit}/CN={HostName}/emailAddress={EmailAddress}";

            using (var KeyPropsFile = new KillHandle())
            {
                Logger.Debug("Writing Props to {0}", KeyPropsFile.FileName);
                KeyPropsFile.WriteAllLines(new string[] {
                    "[req]",
                    "req_extensions = v3_req",
                    "[v3_req]",
                    SAN != null && SAN.Length > 0 ? "subjectAltName=" + SanLine(SAN) : ""
                });
                using (var PrivateKeyFile = new KillHandle())
                {
                    Logger.Debug("Using {0} as Private Key File", PrivateKeyFile.FileName);
                    PrivateKeyFile.WriteAllText(PrivateKey);
                    using (var CaKeyFile = new KillHandle())
                    {
                        Logger.Debug("Using {0} as CA Key File", CaKeyFile.FileName);
                        CaKeyFile.WriteAllText(RootKey);
                        using (var CaCertFile = new KillHandle())
                        {
                            Logger.Debug("Using {0} as CA Cert File", CaCertFile.FileName);
                            CaCertFile.WriteAllText(CaCert);

                            //Make a proper Certificate Request
                            Logger.Debug("Making Cert Request");
                            var ExeParams = new string[]
                            {
                                "req",
                                "-new",
                                "-key",
                                PrivateKeyFile.FileName,
                                UseSha256 ? "-sha256" : "-sha1",
                                //"-nodes",
                                "-extensions",
                                "v3_req",
                                "-subj",
                                Subject
                            };
                            using (var ReqFile = new KillHandle())
                            {
                                var Req = Run(ExeParams);
                                Logger.Debug("Request:\n{0}", Req);
                                ReqFile.WriteAllText(Req);

                                //Sign the Request with the CA key
                                ExeParams = new string[]
                                {
                                    "x509",
                                    "-req",
                                    UseSha256 ? "-sha256" : "-sha1",
                                    "-extensions",
                                    "v3_req",
                                    "-extfile",
                                    KeyPropsFile.FileName,
                                    "-days",
                                    ExpirationDays.ToString(),
                                    "-in",
                                    ReqFile.FileName,
                                    "-CA",
                                    CaCertFile.FileName,
                                    "-CAkey",
                                    CaKeyFile.FileName,
                                    "-CAcreateserial"
                                };
                                var Cert = Run(ExeParams);
                                Logger.Debug("Certificate:\n{0}", Cert);
                                return Cert;
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Extracts the public Key of an RSA key or Certificate
        /// </summary>
        /// <param name="Content">RSA or Certificate content</param>
        /// <param name="IsCert">True for Certificate, false for RSA private key</param>
        /// <returns>Public key</returns>
        public static string GetPubKey(string Content, bool IsCert)
        {
            Logger.Debug("Extracting Public key. IsCert={0}", IsCert);
            using (var IN = new KillHandle())
            {
                IN.WriteAllText(Content);
                if (IsCert)
                {
                    return Run("x509", "-in", IN.FileName, "-pubkey", "-noout");
                }
                else
                {
                    return Run("rsa", "-in", IN.FileName, "-pubout");
                }
            }
        }

        /// <summary>
        /// Creates a PFX file
        /// </summary>
        /// <param name="Certificate">Main Certificate</param>
        /// <param name="PrivateKey">Private Key of Certificate</param>
        /// <param name="Parents">Parent certificates</param>
        /// <param name="Password">Password</param>
        /// <returns>PFX binary</returns>
        public static byte[] CreatePfx(string Certificate, string PrivateKey, string[] Parents, string Password)
        {
            Logger.Log("Creating PFX file.");
            using (var PfxFile = new KillHandle())
            {
                using (var CertFile = new KillHandle())
                {
                    if (Parents == null)
                    {
                        CertFile.WriteAllText(Certificate);
                    }
                    else
                    {
                        CertFile.WriteAllLines(Parents.Concat(new string[] { Certificate }).ToArray());
                    }
                    using (var KeyFile = new KillHandle())
                    {
                        KeyFile.WriteAllText(PrivateKey);
                        var args = new string[] {
                            "pkcs12",
                            "-export",
                            "-in",
                            CertFile.FileName,
                            "-inkey",
                            KeyFile.FileName,
                            "-out",
                            PfxFile.FileName,
                            "-passout",
                            $"pass:{Password}"
                        };
                        if (Parents != null && Parents.Length > 0)
                        {
                            using (var ParentFile = new KillHandle())
                            {
                                ParentFile.WriteAllLines(Parents);
                                Run(args);
                            }
                        }
                        else
                        {
                            Run(args);
                        }
                    }
                }
                return PfxFile.ReadAllBytes();
            }
        }

        /// <summary>
        /// Runs openssl and returns console output
        /// </summary>
        /// <param name="Args">Arguments</param>
        /// <returns>Console Output</returns>
        private static string Run(params object[] Args)
        {
            var Sanitized = Args
                .Where(m => m != null)
                .Select(m => NeedEscape($"{m}") ? $"\"{m.ToString().Replace("\"", "").Replace('\\', '/')}\"" : m.ToString())
                .ToArray();
            Logger.Debug("Exec:\r\n{0} {1}", OPENSSL_COMMAND, string.Join(" ", Sanitized));
            using (var P = new Process())
            {
                P.StartInfo.FileName = OPENSSL_COMMAND;
                if (Args != null && Args.Length > 0)
                {
                    P.StartInfo.Arguments = string.Join(" ", Sanitized);
                }
                else
                {
                    throw new ArgumentException("Arguments required but absent");
                }
                P.StartInfo.CreateNoWindow = true;
                P.StartInfo.UseShellExecute = false;
                P.StartInfo.RedirectStandardOutput = true;
#if LOG_STDERR
                P.StartInfo.RedirectStandardError = true;
#endif
                try
                {
                    P.Start();
#if LOG_STDERR
                    var Task = P.StandardError.ReadToEndAsync();
                    var Stdout = P.StandardOutput.ReadToEnd().Trim();
                    var Stderr = Task.Result;
                    Logger.Debug("openssl error: {0}", Stderr);
                    Logger.Debug("openssl output: {0}", Stdout);
                    if (P.ExitCode != 0)
                    {
                        Logger.Warn("OpenSSL exited with non-zero code {0}", P.ExitCode);
                    }
                    return Stdout;
#else
                    var Stdout = P.StandardOutput.ReadToEnd().Trim();
                    if (P.ExitCode != 0)
                    {
                        Logger.Warn("OpenSSL exited with non-zero code {0}", P.ExitCode);
                    }
                    return Stdout;
#endif
                }
                catch (Exception ex)
                {
                    throw new Exception($"Unable to run {OPENSSL_COMMAND}. See inner exception for details", ex);
                }
            }
        }

        /// <summary>
        /// Checks if a command line argument needs to be put in quotes
        /// </summary>
        /// <param name="s">String</param>
        /// <returns>true if escaping is necessary</returns>
        /// <remarks>Using quotes will create problems if the argument contains quotes itself</remarks>
        private static bool NeedEscape(string s)
        {
            const string INVALID = "\"'|< >{}[]?*/\\";
            return s.ToCharArray().Any(m => INVALID.Contains(m));
        }

        /// <summary>
        /// Creates a SAN line for openssl
        /// </summary>
        /// <param name="SAN">Host list</param>
        /// <returns>SAN Line</returns>
        private static string SanLine(string[] SAN)
        {
            var RET = new string[SAN.Length];
            int IpCount = 0;
            int DnsCount = 0;
            for (var i = 0; i < RET.Length; i++)
            {
                var S = SAN[i];
                if (Tools.IsValidIp(S))
                {
                    RET[i] = string.Format("IP.{0}:{1}", ++IpCount, S);
                }
                else if (Tools.IsValidDomainName(S))
                {
                    RET[i] = string.Format("DNS.{0}:{1}", ++DnsCount, S);
                }
                else
                {
                    Logger.Error("SAN has invalid Domain or IP: {0}", S);
                    throw new FormatException($"SAN has invalid Domain or IP: {S}");
                }
            }
            Logger.Debug("SAN: {0}", string.Join(",", RET));
            return string.Join(",", RET);
        }
    }
}
