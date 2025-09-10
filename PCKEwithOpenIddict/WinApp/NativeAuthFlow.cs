using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;
using Duende.IdentityModel.OidcClient;
using Duende.IdentityModel.OidcClient.Browser;
using CefSharp;
using CefSharp.WinForms;

namespace WinApp
{
    public class NativeAuthFlow
    {
        private readonly string idpAuthority = "https://localhost:7199";
        private readonly string clientId = "demo_client_pkce"; // must be registered in your IdP
        private readonly string redirectUri = "http://127.0.0.1:7890/"; // loopback redirect
        private ChromiumWebBrowser browser;

        public async Task PerformLoginAndOpenWebBAsync(Form parentForm)
        {
            // 1) Configure OIDC client
            var options = new OidcClientOptions
            {
                Authority = idpAuthority,
                ClientId = clientId,
                RedirectUri = redirectUri,
                Scope = "api openid profile",
                Browser = new SystemBrowser(7890),

                // Policy is still fine to customize
                Policy = new Policy
                {
                    RequireIdentityTokenSignature = false
                }

                // Note: ResponseType defaults to "code" already.
                // If you want to be explicit, you can do:
                // ResponseType = "code"
            };

            var oidc = new OidcClient(options);
            var result = await oidc.LoginAsync(new LoginRequest());

            if (result.IsError)
            {
                MessageBox.Show("Login error: " + result.Error);
                return;
            }

            var idToken = result.IdentityToken; // pass this to Web Interface

            // 2) POST id_token to Web Interface /api/sso/exchange
            using (var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }))
            {
                var webInterfaceBaseUrl = "https://localhost:7087";
                http.BaseAddress = new Uri(webInterfaceBaseUrl);

                var payload = new { IdToken = idToken };
                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var resp = await http.PostAsync("/api/sso/exchange", content);

                if (!resp.IsSuccessStatusCode)
                {
                    var text = await resp.Content.ReadAsStringAsync();
                    MessageBox.Show("Exchange failed: " + resp.StatusCode + " " + text);
                    return;
                }

                // 3) Take Set-Cookie header(s) and load into CefSharp’s cookie store
                var setCookieHeaders = resp.Headers
                    .Where(h => h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                    .SelectMany(h => h.Value)
                    .ToList();

                // Initialize Cef if needed
                if (!Cef.IsInitialized.GetValueOrDefault(false))
                {
                    Cef.Initialize(new CefSettings());
                }

                // Create browser if not already
                if (browser == null)
                {
                    browser = new ChromiumWebBrowser("about:blank")
                    {
                        Dock = DockStyle.Fill
                    };
                    parentForm.Controls.Add(browser);
                }

                var cookieManager = Cef.GetGlobalCookieManager();

                foreach (var sc in setCookieHeaders)
                {
                    // naive cookie parsing (for demo only)
                    var parts = sc.Split(';')
                                  .Select(p => p.Trim())
                                  .ToArray();

                    var nameValue = parts[0];
                    var idx = nameValue.IndexOf('=');
                    var name = nameValue.Substring(0, idx);
                    var value = nameValue.Substring(idx + 1);

                    var domainPart = parts.FirstOrDefault(p => p.StartsWith("Domain=", StringComparison.OrdinalIgnoreCase));
                    var domain = domainPart != null ? domainPart.Substring("Domain=".Length) : "localhost";

                    var cookie = new CefSharp.Cookie
                    {
                        Name = name,
                        Value = value,
                        Domain = domain,
                        Path = "/",
                        Secure = true,
                        HttpOnly = true
                    };

                    await cookieManager.SetCookieAsync(webInterfaceBaseUrl, cookie);
                }

                // 4) Navigate to Web Interface, now authenticated
                browser.Load(webInterfaceBaseUrl);
            } 
        }
    }
}