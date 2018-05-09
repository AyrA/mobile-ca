using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace mobile_ca
{
    public class Server : IDisposable
    {
        #region API Types

        private class ApiConfig
        {
            public int[] sizes = CertCommands.ValidKeySizes
                .Where(m => m <= 4096)
                .OrderByDescending(m => m)
                .ToArray();
        }

        private class ApiPfxRequest
        {
            public string key;
            public string cert;
            public string[] parents;
            public string password;
        }

        private class ApiThumbprint
        {
            public string id;
        }

        private class ApiId
        {
            public Guid id;
        }

        private class ApiGenRsaKey
        {
            public int keySize = 0;
        }

        private class ApiRsaKey
        {
            public string id;
            public string key;
            public string pubkey;

            public ApiRsaKey(string FileName)
            {
                key = File.ReadAllText(FileName);
                id = Path.GetFileNameWithoutExtension(FileName);
                pubkey = CertCommands.GetPubKey(key, false);
            }
            public ApiRsaKey()
            {
                id = Guid.NewGuid().ToString();
            }
        }

        private class ApiCert
        {
            public string hash;
            public string data;
            public string name;
            public string pubkey;
            public string issuer;
            public string domain;
            public string[] san;
            public DateTime start;
            public DateTime end;

            public ApiCert()
            {
            }

            public ApiCert(string FileName, string[] ParentFiles)
            {
                data = File.ReadAllText(FileName);
                var Cert = CertStore.GetCert(data);
                hash = Cert.Thumbprint;
                san = CertStore.GetSan(data);
                domain = CertStore.GetName(data);
                name = Cert.Subject;
                pubkey = CertCommands.GetPubKey(data, true);
                issuer = CertStore.GetSignerCertHash(data, ParentFiles);
                start = Cert.NotBefore;
                end = Cert.NotAfter;
            }
        }

        private class ApiCACert
        {
            public string hash;
            public string data;
            public string name;
            public string pubkey;
            public DateTime start;
            public DateTime end;

            public ApiCACert()
            {
            }

            public ApiCACert(string FileName)
            {
                data = File.ReadAllText(FileName);
                var Cert = CertStore.GetCert(data);
                hash = Cert.Thumbprint;
                name = CertStore.GetName(data);
                pubkey = CertCommands.GetPubKey(data, true);
                start = Cert.NotBefore;
                end = Cert.NotAfter;
            }
        }

        private class ApiCaCreate
        {
            public Guid id = Guid.Empty;
            public string cc = "XX";
            public string st = "Local";
            public string l = "Local";
            public string o = "ACME";
            public string ou = "ACME";
            public string cn = "ACME Root CA";
            public string e = "ACME@example.com";
            public int exp = 3650;
            public bool sha256 = false;

            public bool Valid()
            {
                return id != Guid.Empty &&
                    !string.IsNullOrEmpty(cc) &&
                    !string.IsNullOrEmpty(st) &&
                    !string.IsNullOrEmpty(l) &&
                    !string.IsNullOrEmpty(o) &&
                    !string.IsNullOrEmpty(ou) &&
                    !string.IsNullOrEmpty(cn) &&
                    !string.IsNullOrEmpty(e);
            }
        }

        private class ApiCertCreate
        {
            public Guid id = Guid.Empty;
            public string cc = "XX";
            public string st = "Local";
            public string l = "Local";
            public string o = "ACME";
            public string ou = "ACME";
            public string cn = "acme.local";
            public string e = "ACME@example.com";
            public string[] san = null;
            public string parent = null;
            public int exp = 365;
            public bool sha256 = false;

            public bool Valid()
            {
                return id != Guid.Empty &&
                    !string.IsNullOrEmpty(cc) &&
                    !string.IsNullOrEmpty(st) &&
                    !string.IsNullOrEmpty(l) &&
                    !string.IsNullOrEmpty(o) &&
                    !string.IsNullOrEmpty(ou) &&
                    !string.IsNullOrEmpty(cn) &&
                    !string.IsNullOrEmpty(e) &&
                    CertStore.IsSHA1(parent);
            }
        }

        #endregion

        public string BaseURL { get; private set; }
        public string Base { get; private set; }
        public bool IsListening
        {
            get
            {
                return L != null && L.IsListening;
            }
        }
        private class BinaryContent
        {
            public string URL;
            public byte[] Data;
            public bool IsUtf8;
            public string Hash;

            public BinaryContent(string URL, byte[] Content, bool IsUtf8)
            {
                this.URL = URL;
                Data = Content;
                Hash = Server.Hash(Content);
                this.IsUtf8 = IsUtf8;
            }
            public BinaryContent(string URL, string Content, bool IsUtf8) : this(URL, Encoding.UTF8.GetBytes(Content), IsUtf8)
            {
            }
        }

        private static readonly List<BinaryContent> LocalContent = new List<BinaryContent>
        {
            new BinaryContent("/bootstrap.css",Properties.Resources.bootstrap_css,true),
            new BinaryContent("/bootstrap.js",Properties.Resources.bootstrap_js,true),
            new BinaryContent("/jquery.js",Properties.Resources.jquery_slim_js,true),
            new BinaryContent("/popper.js",Properties.Resources.popper_js,true),
            new BinaryContent("/index.html",Properties.Resources.index_html,true),
            new BinaryContent("/api.js",Properties.Resources.api_js,true),
            new BinaryContent("/custom.css",Properties.Resources.custom_css,true)
        };

        private HttpListener L;

        public static bool IsValidPort(int Port)
        {
            return Port > ushort.MinValue && Port < ushort.MaxValue;
        }

        public Server(int Port, bool StartBrowser = false, string CertBasePath = "<proc>")
        {
            if (string.IsNullOrEmpty(CertBasePath))
            {
                throw new ArgumentException("Invalid Base Path");
            }
            Base = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(CertBasePath == "<proc>" ? Process.GetCurrentProcess().MainModule.FileName : CertBasePath)), "Data");
            if (!IsValidPort(Port))
            {
                throw new ArgumentOutOfRangeException("Port");
            }
            Logger.Debug("HTTP: Base Path: {0}", Base);
            if (!Directory.Exists(Base))
            {
                try
                {
                    Directory.CreateDirectory(Base);
                    Logger.Info("HTTP: Created base directory");
                }
                catch (Exception ex)
                {
                    Logger.Error("HTTP: Unable to create Base path {0}. Reason: {1}", Base, ex.Message);
                }
            }


            BaseURL = $"http://localhost:{Port}/";
            Logger.Info("HTTP: Starting Webserver on {0}", BaseURL);
            L = new HttpListener();
            L.Prefixes.Add(BaseURL);
            L.IgnoreWriteExceptions = true;
            L.Start();
            L.BeginGetContext(conin, L);
            if (StartBrowser)
            {
                try
                {
                    //Calling Dispose() yourself will somehow throw an exception
                    //but with the using(...) it does not.
                    using (Process.Start(BaseURL)) { }
                }
                catch (Exception ex)
                {
                    Logger.Warn("HTTP: Unable to start browser for {0}. Reason: {1}", Base, ex.Message);
                }
            }
        }

        public void Dispose()
        {
            Logger.Debug("HTTP: Disposing Webserver");
            Shutdown();
        }

        public void Shutdown()
        {
            lock (this)
            {
                if (L != null)
                {
                    Logger.Info("HTTP: Server shutdown");
                    L.Stop();
                    L = null;
                }
                else
                {
                    Logger.Info("HTTP: Server shutdown attempt but was already");
                }
            }
        }

        private void conin(IAsyncResult ar)
        {
            var L = (HttpListener)ar.AsyncState;
            if (L != null && L.IsListening)
            {
                var ctx = L.EndGetContext(ar);
                HandleRequest(ctx);
                L.BeginGetContext(conin, L);
            }
        }

        private void HandleRequest(HttpListenerContext ctx)
        {
            if (ctx != null)
            {
                Thread T = new Thread(Answer);
                T.Priority = ThreadPriority.BelowNormal;
                T.IsBackground = true;
                T.Start(ctx);
            }
        }

        private void Answer(object o)
        {
            var ctx = (HttpListenerContext)o;
            //Setting Security Headers
            ctx.Response.AddHeader("X-Frame-Options", "SAMEORIGIN");
            ctx.Response.AddHeader("X-XSS-Protection", "1; mode=block");
            ctx.Response.AddHeader("X-Content-Type-Options", "nosniff");
            ctx.Response.AddHeader("Referrer-Policy", "same-origin");
            ctx.Response.AddHeader("Content-Security-Policy",
                "default-src 'none';" +
                "script-src 'self';" +
                "style-src 'self' 'unsafe-inline';" +
                "connect-src 'self';" +
                "form-action 'self';" +
                "block-all-mixed-content");
            if (ctx.Request.Url.Scheme.ToLower() == "https")
            {
                ctx.Response.AddHeader("Strict-Transport-Security", "max-age=15552000");
            }

            Logger.Log("HTTP: {0} {1}", ctx.Request.HttpMethod, ctx.Request.Url.AbsolutePath);
            switch (ctx.Request.HttpMethod.ToLower())
            {
                case "get":
                    if (ctx.Request.Url.AbsolutePath.StartsWith("/~/"))
                    {
                        try
                        {
                            DeliverLocal(ctx);
                        }
                        catch (Exception ex)
                        {
                            Logger.Error("HTTP: Unable to deliver local file. Reason: {0}", ex.Message);
                            HTTP500(ctx, ex);
                        }
                    }
                    else
                    {
                        try
                        {
                            Deliver(ctx);
                        }
                        catch (Exception ex)
                        {
                            Logger.Error("HTTP: Unable to deliver API request. Reason: {0}", ex.Message);
                            HTTP500(ctx, ex);
                        }
                    }
                    break;
                case "post":
                    if (!ctx.Request.Url.AbsolutePath.StartsWith("/~/"))
                    {
                        try
                        {
                            Deliver(ctx);
                        }
                        catch (Exception ex)
                        {
                            Logger.Error("HTTP: Unable to deliver API request. Reason: {0}", ex.Message);
                            HTTP500(ctx, ex);
                        }
                    }
                    else
                    {
                        HTTP404(ctx);
                    }
                    break;
                default:
                    ctx.Response.StatusCode = 405;
                    ctx.Response.Close();
                    break;
            }
        }

        private void Deliver(HttpListenerContext ctx)
        {
            Logger.Debug("HTTP: API Request");
            switch (ctx.Request.Url.AbsolutePath.ToLower())
            {
                case "/":
                    Redirect(ctx, "/~/");
                    break;
                case "/config":
                    Config(ctx);
                    break;
                case "/genca":
                    GenCA(ctx);
                    break;
                case "/getca":
                    GetCA(ctx);
                    break;
                case "/delca":
                    DelCA(ctx);
                    break;
                case "/gencert":
                    GenCert(ctx);
                    break;
                case "/getcert":
                    GetCert(ctx);
                    break;
                case "/delcert":
                    DelCert(ctx);
                    break;
                case "/getkeys":
                    GetKeys(ctx);
                    break;
                case "/delkey":
                    DelKey(ctx);
                    break;
                case "/genkey":
                    GenKey(ctx);
                    break;
                case "/pfx":
                    CreatePfx(ctx);
                    break;
                default:
                    HTTP404(ctx);
                    break;
            }
        }

        private void DeliverLocal(HttpListenerContext ctx)
        {
            Logger.Debug("HTTP: local resource");
            var URL = ctx.Request.Url.AbsolutePath.ToLower().Substring(2);
            var Entry = LocalContent.FirstOrDefault(m => m.URL == URL);
            if (Entry != null && Entry.URL == URL)
            {
                ctx.Response.AddHeader("ETag", Entry.Hash);
                var Hash = ctx.Request.Headers["If-None-Match"];
                if (Hash != null && Hash == Entry.Hash)
                {
                    ctx.Response.ContentType = MimeTypeLookup.GetMimeType(Entry.URL) + (Entry.IsUtf8 ? ";charset=utf-8" : "");
                    ctx.Response.StatusCode = 304;
                    ctx.Response.Close();
                }
                else
                {
                    SendBinary(ctx, Entry.Data, Entry.URL, Entry.IsUtf8);
                }
            }
            else if (URL == "/")
            {
                Redirect(ctx, "/~/index.html");
            }
            else
            {
                HTTP404(ctx);
            }
        }

        #region HTTP Answer types

        private void SendBinary(HttpListenerContext ctx, byte[] Content, string FakeName, bool IsUtf8 = false)
        {
            Logger.Debug("HTTP: Sending {0} ({1} bytes)", FakeName, Content == null ? 0 : Content.Length);
            ctx.Response.ContentType = MimeTypeLookup.GetMimeType(FakeName) + (IsUtf8 ? ";charset=utf-8" : "");
            ctx.Response.Close(Content, false);
        }

        private void SendString(HttpListenerContext ctx, string Content, string FakeName)
        {
            SendBinary(ctx, Encoding.UTF8.GetBytes(Content), FakeName, true);
        }

        private void SendFile(HttpListenerContext ctx, string file)
        {
            Logger.Debug("HTTP: Sending {0}", file);
            ctx.Response.ContentType = MimeTypeLookup.GetMimeType(file);
            ctx.Response.Close(File.ReadAllBytes(file), false);
        }

        private void SendJson(HttpListenerContext ctx, object O, bool success)
        {
            Logger.Debug("HTTP: Sending JSON for {0}", O);
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentEncoding = Encoding.UTF8;
            ctx.Response.Close(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { success = success, data = O })), false);
        }

        private void Redirect(HttpListenerContext ctx, string NewUrl, bool Permanent = false)
        {
            Logger.Debug("HTTP: Redirecting to {0} Permanent={1}", NewUrl, Permanent);
            ctx.Response.StatusCode = Permanent ? 301 : 307;
            ctx.Response.Headers.Add(HttpResponseHeader.Location, NewUrl);
            ctx.Response.Close();
        }

        private void HTTP404(HttpListenerContext ctx)
        {
            Logger.Debug("HTTP: Sending 404");
            ctx.Response.StatusCode = 404;
            ctx.Response.Close();
        }

        private void HTTP500(HttpListenerContext ctx, Exception ex)
        {
            if (ex == null)
            {
                ex = new Exception("Unknown error");
            }
            Logger.Warn("HTTP: Sending 500 due to server error.");
            try
            {
                ctx.Response.StatusCode = 500;
                ctx.Response.ContentType = "text/plain";
                ctx.Response.ContentEncoding = Encoding.UTF8;
                ctx.Response.Close(Encoding.UTF8.GetBytes(string.Format(@"HTTP 500 - I screwed up.
Due to an unforseen error we are unable to execute your current request.
If this keeps happening, please inform the developer.

Details
=======

Error: {0}

Location:
{1}", ex.Message, ex.StackTrace)), false);
            }
            catch (Exception E)
            {
                Logger.Error("HTTP: Unable to send HTTP 500. Message: {0}", E.Message);
                try
                {
                    ctx.Response.Abort();
                }
                catch
                {
                    //At this point we no longer care
                }
            }
        }

        #endregion

        #region API

        private void Config(HttpListenerContext ctx)
        {
            if (ctx.Request.HttpMethod.ToLower() == "get")
            {
                SendJson(ctx, new ApiConfig(), true);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        private void CreatePfx(HttpListenerContext ctx)
        {
            if (ctx.Request.HasEntityBody)
            {
                var Req = FromJson<ApiPfxRequest>(ReadAllText(ctx.Request.InputStream, ctx.Request.ContentEncoding));
                if (Req != null && !string.IsNullOrWhiteSpace(Req.cert) && !string.IsNullOrWhiteSpace(Req.key))
                {
                    var Data = CertCommands.CreatePfx(Req.cert, Req.key, Req.parents, Req.password);
                    SendJson(ctx, Data, Data != null && Data.Length > 0);
                    return;
                }
                SendJson(ctx, "Invalid Request Content", false);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        private void DelCert(HttpListenerContext ctx)
        {
            if (ctx.Request.HasEntityBody)
            {
                var Req = FromJson<ApiThumbprint>(ReadAllText(ctx.Request.InputStream, ctx.Request.ContentEncoding));
                if (Req != null && !string.IsNullOrEmpty(Req.id))
                {
                    var FileName = Path.Combine(Base, Req.id + ".cli.crt");
                    if (File.Exists(FileName))
                    {
                        try
                        {
                            File.Delete(FileName);
                            SendJson(ctx, Req.id, true);
                            return;
                        }
                        catch (Exception ex)
                        {
                            Logger.Error("HTTP: Unable to delete file {0}. Reason: {1}", FileName, ex.Message);
                            SendJson(ctx, "Unable to delete file", false);
                            return;
                        }
                    }
                    SendJson(ctx, "Invalid ID", false);
                    return;
                }
                SendJson(ctx, "Invalid Request Content", false);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        private void GetCert(HttpListenerContext ctx)
        {
            if (ctx.Request.HttpMethod.ToLower() == "get")
            {
                var CA = Directory.GetFiles(Base, "*.ca.crt").Select(m => File.ReadAllText(m)).ToArray();
                SendJson(ctx, Directory.GetFiles(Base, "*.cli.crt").Select(m => new ApiCert(m, CA)).ToArray(), true);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        private void GenCert(HttpListenerContext ctx)
        {
            if (ctx.Request.HasEntityBody)
            {
                var Req = FromJson<ApiCertCreate>(ReadAllText(ctx.Request.InputStream, ctx.Request.ContentEncoding));
                if (Req != null && Req.Valid())
                {
                    string Key = null;
                    string RootCert = null;
                    string RootKey = null;
                    var KeyFileName = Path.Combine(Base, Req.id.ToString() + ".key");
                    var RootFileName = Path.Combine(Base, Req.parent.ToString() + ".ca.crt");
                    if (File.Exists(KeyFileName))
                    {
                        if (File.Exists(RootFileName))
                        {
                            try
                            {
                                Key = File.ReadAllText(KeyFileName);
                            }
                            catch (Exception ex)
                            {
                                Logger.Error("HTTP: Unable to read file {0}. Reason: {1}", KeyFileName, ex.Message);
                                SendJson(ctx, "Unable to read key file", false);
                                return;
                            }
                            try
                            {
                                RootCert = File.ReadAllText(RootFileName);
                            }
                            catch (Exception ex)
                            {
                                Logger.Error("HTTP: Unable to read file {0}. Reason: {1}", RootFileName, ex.Message);
                                SendJson(ctx, "Unable to read CA file", false);
                                return;
                            }

                            //Figure out the matching private key for the given root certificate
                            var RootPub = CertCommands.GetPubKey(RootCert, true);
                            RootKey = Directory.GetFiles(Base, "*.key")
                                .Select(m => File.ReadAllText(m))
                                .FirstOrDefault(m => CertCommands.GetPubKey(m, false) == RootPub);

                            if (!string.IsNullOrEmpty(RootKey))
                            {
                                try
                                {
                                    var Cert = CertCommands.GenerateCertificate(RootKey, RootCert, Key, Req.cn, Req.san, Req.exp, Req.sha256, Req.cc, Req.st, Req.l, Req.o, Req.ou, Req.e);
                                    var Id = CertStore.GetThumb(Cert);
                                    var CertFileName = Path.Combine(Base, Id + ".cli.crt");
                                    File.WriteAllText(CertFileName, Cert);
                                    SendJson(ctx, new ApiCert(CertFileName, new string[] { RootCert }), true);
                                    return;
                                }
                                catch (Exception ex)
                                {
                                    SendJson(ctx, string.Format("CA creation error: {0}", ex.Message), false);
                                    return;
                                }
                            }
                            SendJson(ctx, "Unable to locate private key of the give nroot certificate", false);
                            return;
                        }
                        SendJson(ctx, "Invalid root Thumbprint", false);
                        return;
                    }
                    SendJson(ctx, "Invalid Key ID", false);
                    return;
                }
                SendJson(ctx, "Invalid Request Content", false);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        private void DelCA(HttpListenerContext ctx)
        {
            if (ctx.Request.HasEntityBody)
            {
                var Req = FromJson<ApiThumbprint>(ReadAllText(ctx.Request.InputStream, ctx.Request.ContentEncoding));
                if (Req != null && !string.IsNullOrEmpty(Req.id))
                {
                    var FileName = Path.Combine(Base, Req.id + ".ca.crt");
                    if (File.Exists(FileName))
                    {
                        try
                        {
                            File.Delete(FileName);
                            SendJson(ctx, Req.id, true);
                            return;
                        }
                        catch (Exception ex)
                        {
                            Logger.Error("HTTP: Unable to delete file {0}. Reason: {1}", FileName, ex.Message);
                            SendJson(ctx, "Unable to delete file", false);
                            return;
                        }
                    }
                    SendJson(ctx, "Invalid ID", false);
                    return;
                }
                SendJson(ctx, "Invalid Request Content", false);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        private void GenCA(HttpListenerContext ctx)
        {
            if (ctx.Request.HasEntityBody)
            {
                var Req = FromJson<ApiCaCreate>(ReadAllText(ctx.Request.InputStream, ctx.Request.ContentEncoding));
                if (Req != null && Req.Valid())
                {
                    string Key = null;
                    var KeyFileName = Path.Combine(Base, Req.id.ToString() + ".key");
                    if (File.Exists(KeyFileName))
                    {
                        try
                        {
                            Key = File.ReadAllText(KeyFileName);
                        }
                        catch (Exception ex)
                        {
                            Logger.Error("HTTP: Unable to read file {0}. Reason: {1}", KeyFileName, ex.Message);
                            SendJson(ctx, "Unable to read key file", false);
                            return;
                        }
                        try
                        {
                            var Cert = CertCommands.GenerateRootCert(Key, Req.exp, Req.sha256, Req.cc, Req.st, Req.l, Req.o, Req.ou, Req.cn, Req.e);
                            var Id = CertStore.GetThumb(Cert);
                            var CertFileName = Path.Combine(Base, Id + ".ca.crt");
                            File.WriteAllText(CertFileName, Cert);
                            SendJson(ctx, new ApiCACert(CertFileName), true);
                            return;
                        }
                        catch (Exception ex)
                        {
                            SendJson(ctx, string.Format("CA creation error: {0}", ex.Message), false);
                            return;
                        }
                    }
                    SendJson(ctx, "Invalid Key file ID", false);
                    return;
                }
                SendJson(ctx, "Invalid Request Content", false);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        private void GetCA(HttpListenerContext ctx)
        {
            if (ctx.Request.HttpMethod.ToLower() == "get")
            {
                SendJson(ctx, Directory.GetFiles(Base, "*.ca.crt").Select(m => new ApiCACert(m)).ToArray(), true);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        private void DelKey(HttpListenerContext ctx)
        {
            if (ctx.Request.HasEntityBody)
            {
                var Req = FromJson<ApiId>(ReadAllText(ctx.Request.InputStream, ctx.Request.ContentEncoding));
                if (Req != null && Req.id != Guid.Empty)
                {
                    var FileName = Path.Combine(Base, Req.id.ToString() + ".key");
                    if (File.Exists(FileName))
                    {
                        try
                        {
                            File.Delete(FileName);
                            SendJson(ctx, Req.id, true);
                            return;
                        }
                        catch (Exception ex)
                        {
                            Logger.Error("HTTP: Unable to delete file {0}. Reason: {1}", FileName, ex.Message);
                            SendJson(ctx, "Unable to delete file", false);
                            return;
                        }
                    }
                    SendJson(ctx, "Invalid ID", false);
                    return;
                }
                SendJson(ctx, "Invalid Request Content", false);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        private void GetKeys(HttpListenerContext ctx)
        {
            if (ctx.Request.HttpMethod.ToLower() == "get")
            {
                SendJson(ctx, Directory.GetFiles(Base, "*.key").Select(m => new ApiRsaKey(m)), true);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        private void GenKey(HttpListenerContext ctx)
        {
            if (ctx.Request.HasEntityBody)
            {
                var Req = FromJson<ApiGenRsaKey>(ReadAllText(ctx.Request.InputStream, ctx.Request.ContentEncoding));
                if (Req != null && CertCommands.IsValidKeySize(Req.keySize))
                {
                    var Key = CertCommands.GenerateKey(Req.keySize);
                    if (!string.IsNullOrEmpty(Key))
                    {
                        var KeyData = new ApiRsaKey();
                        KeyData.key = Key;
                        var FileName = Path.Combine(Base, KeyData.id + ".key");
                        try
                        {
                            File.WriteAllText(FileName, KeyData.key);
                            SendJson(ctx, new ApiRsaKey(FileName), true);
                            return;
                        }
                        catch (Exception ex)
                        {
                            Logger.Error("HTTP: Unable to save generated key to {0}. Reason: {1}", FileName, ex.Message);
                        }
                        SendJson(ctx, "Unable to write Key to filesystem", false);
                        return;
                    }
                    SendJson(ctx, "Unable to generate key", false);
                    return;
                }
                SendJson(ctx, "Invalid Request Content", false);
                return;
            }
            SendJson(ctx, "Invalid Request Method", false);
        }

        #endregion

        #region UTILS

        private static string Hash(byte[] Content)
        {
            using (var HA = new SHA1Managed())
            {
                return BitConverter.ToString(HA.ComputeHash(Content)).Replace("-", "");
            }
        }

        private static string Hash(string Content)
        {
            return Hash(Encoding.UTF8.GetBytes(Content));
        }

        private static T FromJson<T>(string JSON, T Default = default(T))
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

        private static string ReadAllText(Stream S, Encoding E = null)
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

        #endregion
    }
}
