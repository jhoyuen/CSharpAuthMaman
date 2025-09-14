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
        // NEVER DO THAT IN PROD, THIS IS JUST TO GET THE DEMO WORKING EASILY
        public static string User = "";
        public static string Pass = "";

        private ChromiumWebBrowser browser;

        public async Task PerformLoginAndOpenWebBAsync(Form parentForm)
        {
            var authService = new AuthService();
            var result = await authService.GetAccessToken(User, Pass);

            if (result == null || (result != null && string.IsNullOrEmpty(result.id_token))) {
                MessageBox.Show("Login error: no result");
                return;
            }
            var idToken = result.id_token; // pass this to Web Interface

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

        public async Task UseTokenToLoginWebInterfaceAsync(string accessToken, string idToken)
        {
            using (var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }))
            {
                var webInterfaceBaseUrl = "https://localhost:7087";
                http.BaseAddress = new Uri(webInterfaceBaseUrl);

                var payload = new { id_token = idToken };
                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var resp = await http.PostAsync("/api/sso/exchange", content);

                if (!resp.IsSuccessStatusCode)
                {
                    var text = await resp.Content.ReadAsStringAsync();
                    MessageBox.Show($"Web interface login failed: {text}");
                    return;
                }

                // Inject cookies into CefSharp or any embedded browser
                var setCookieHeaders = resp.Headers
                    .Where(h => h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                    .SelectMany(h => h.Value)
                    .ToList();

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

                //// Open web interface
                //browser.Load("https://localhost:7087/");
            }
        }
    }
}