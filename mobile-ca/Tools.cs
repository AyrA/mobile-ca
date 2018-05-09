using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace mobile_ca
{
    /// <summary>
    /// Generic Utilities
    /// </summary>
    public static class Tools
    {
        private static string _procdir;
        
        /// <summary>
        /// Gets the current Process Directory
        /// </summary>
        public static string ProcessDirectory
        {
            get
            {
                if (string.IsNullOrEmpty(_procdir))
                {
                    using (var P = Process.GetCurrentProcess())
                    {
                        _procdir = Path.GetDirectoryName(P.MainModule.FileName);
                    }
                }
                return _procdir;
            }
        }

        /// <summary>
        /// Checks if the given string is a valid SHA1 hash
        /// </summary>
        /// <param name="s">Hash</param>
        /// <returns>true if SHA1</returns>
        public static bool IsSHA1(string s)
        {
            if (!string.IsNullOrEmpty(s))
            {
                var R = new Regex(@"^[\da-fA-F]{40}$");
                return R.IsMatch(s);
            }
            return false;
        }

        /// <summary>
        /// Calculates the SHA1 from a byte array
        /// </summary>
        /// <param name="Content">Byte array</param>
        /// <returns>SHA1</returns>
        public static string Hash(byte[] Content)
        {
            using (var HA = new SHA1Managed())
            {
                return BitConverter.ToString(HA.ComputeHash(Content)).Replace("-", "");
            }
        }

        /// <summary>
        /// Calculates the SHA1 from a string
        /// </summary>
        /// <param name="Content">Text</param>
        /// <returns>SHA1</returns>
        /// <remarks>Encodes string as UTF8</remarks>
        private static string Hash(string Content)
        {
            return Hash(Encoding.UTF8.GetBytes(Content));
        }

        /// <summary>
        /// Reads a string as JSON
        /// </summary>
        /// <typeparam name="T">Type to deserialize</typeparam>
        /// <param name="JSON">JSON string</param>
        /// <param name="Default">Default value on errors</param>
        /// <returns>parsed type or default</returns>
        public static T FromJson<T>(this string JSON, T Default = default(T))
        {
            Logger.Debug("HTTP: Decoding {0}", JSON);
            try
            {
                return JsonConvert.DeserializeObject<T>(JSON);
            }
            catch (Exception ex)
            {
                Logger.Debug("HTTP: Failed to decode JSON.\r\nHTTP: Error: {0}\r\n:HTTP: Data: {1}", ex.Message, JSON);
                return Default;
            }
        }

        /// <summary>
        /// Reads all Text from a stream
        /// </summary>
        /// <param name="S">Stream</param>
        /// <param name="E">Encoding</param>
        /// <returns>Text</returns>
        /// <remarks>
        /// This call blocks until the stream is closed.
        /// Don't use on TCP streams directly
        /// </remarks>
        public static string ReadAllText(this Stream S, Encoding E = null)
        {
            if (S == null)
            {
                return null;
            }

            using (var SR = new StreamReader(S, E == null ? Encoding.UTF8 : E, true))
            {
                return SR.ReadToEnd();
            }
        }

        /// <summary>
        /// Checks if the given name is a valid DNS name
        /// </summary>
        /// <param name="Param">Name</param>
        /// <returns>true if valid name</returns>
        public static bool IsValidDomainName(string Param)
        {
            if (!string.IsNullOrEmpty(Param) && Param.Length < 0x100)
            {
                //Remove wildcard mask if available
                if (Param.StartsWith("*."))
                {
                    Param = Param.Substring(2);
                }
                return Uri.CheckHostName(Param) == UriHostNameType.Dns;
            }
            return false;
        }

        /// <summary>
        /// Checks if the given parameter is a valid IP Address
        /// </summary>
        /// <param name="Param">Possible IP Address</param>
        /// <returns>true if IP</returns>
        /// <remarks>Works with IPv4 and IPv6</remarks>
        public static bool IsValidIp(string Param)
        {
            if (!string.IsNullOrEmpty(Param))
            {
                IPAddress A = IPAddress.Any;
                return IPAddress.TryParse(Param, out A);
            }
            return false;
        }

        /// <summary>
        /// Converts an object to an integer or returns default on failure
        /// </summary>
        /// <param name="o">Object to convert</param>
        /// <param name="Default">Default value on error</param>
        /// <returns>Int or Default</returns>
        public static int IntOrDefault(object o, int Default = 0)
        {
            int i = 0;
            return o == null ? Default : (int.TryParse(o.ToString(), out i) ? i : Default);
        }

    }
}
