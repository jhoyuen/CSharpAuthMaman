using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Duende.IdentityModel.Client;
using Duende.IdentityModel;
using System.Collections.Specialized;
using System.Net;

namespace WinApp
{
    public class AuthService
    {
        private readonly string _idpAuthority = "https://localhost:7199";
        private readonly string _clientId = "demo_client_pkce";
        private readonly string _redirectUri = "http://127.0.0.1:7890/";
        public async Task<TokenResponse> GetAccessToken(string user, string pass)
        {
            // 1) Generate PKCE values
            var codeVerifier = GenerateCodeVerifier();
            var codeChallenge = GenerateCodeChallenge(codeVerifier);

            using (var handler = new HttpClientHandler())
            {
                handler.CookieContainer = new CookieContainer();
                handler.AllowAutoRedirect = false; // important! we want to capture redirect manually

                using (var client = new HttpClient(handler))
                {
                    // 2) Authenticate against your custom session endpoint
                    var loginPayload = JsonSerializer.Serialize(new { Username = user, Password = pass });
                    var resp = await client.PostAsync(
                        $"{_idpAuthority}/account/sessions",
                        new StringContent(loginPayload, Encoding.UTF8, "application/json"));

                    resp.EnsureSuccessStatusCode();
                    var json = await resp.Content.ReadAsStringAsync();
                    var sessionToken = JsonDocument.Parse(json).RootElement.GetProperty("sessionToken").GetString();

                    // 3) Build authorize URL
                    var authorizeUrl = new RequestUrl($"{_idpAuthority}/connect/authorize").CreateAuthorizeUrl(
                        clientId: _clientId,
                        responseType: "code",
                        scope: "openid profile api",
                        redirectUri: _redirectUri,
                        state: CryptoRandom.CreateUniqueId(16),
                        nonce: CryptoRandom.CreateUniqueId(16),
                        codeChallenge: codeChallenge,
                        codeChallengeMethod: "S256"
                    );

                    // Wrap with SSO endpoint to set cookie + redirect
                    var ssoUrl = $"{_idpAuthority}/account/sso?sessionToken={WebUtility.UrlEncode(sessionToken)}&returnUrl={WebUtility.UrlEncode(authorizeUrl)}";

                    // 4) Call SSO endpoint (sets cookie, then redirects to authorize)
                    var ssoResp = await client.GetAsync(ssoUrl);
                    if (ssoResp.StatusCode != HttpStatusCode.Redirect)
                        throw new Exception($"Expected redirect, got {ssoResp.StatusCode}");

                    // 5) Follow redirect to /connect/authorize
                    var authorizeResp = await client.GetAsync(ssoResp.Headers.Location);
                    if (authorizeResp.StatusCode != HttpStatusCode.Redirect)
                        throw new Exception($"Expected code redirect, got {authorizeResp.StatusCode}");

                    // 6) Extract code from redirect URI
                    var redirectUri = new Uri(authorizeResp.Headers.Location.ToString());
                    var queryParams = ParseQueryString(redirectUri.Query);
                    string code = queryParams["code"];

                    // 7) Exchange code for token
                    var tokenResp = await client.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
                    {
                        Address = $"{_idpAuthority}/connect/token",
                        ClientId = _clientId,
                        Code = code,
                        RedirectUri = _redirectUri,
                        CodeVerifier = codeVerifier
                    });

                    if (tokenResp.IsError)
                        throw new Exception(tokenResp.Error);

                    return new TokenResponse { access_token = tokenResp.AccessToken, id_token = tokenResp.IdentityToken, expires_in = tokenResp.ExpiresIn, refresh_token = tokenResp.RefreshToken, token_type = tokenResp.TokenType };
                }
            }
        }

        private static NameValueCollection ParseQueryString(string query)
        {
            var nvc = new NameValueCollection();

            if (query.StartsWith("?"))
                query = query.Substring(1);

            foreach (var kv in query.Split('&'))
            {
                var parts = kv.Split(new[] { '=' }, 2);
                var key = Uri.UnescapeDataString(parts[0]);
                var value = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : "";
                nvc.Add(key, value);
            }

            return nvc;
        }
        private static string GenerateCodeVerifier()
        {
            var bytes = new byte[32];
            var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetNonZeroBytes(bytes);
            return Base64UrlEncode(bytes);
        }

        private static string GenerateCodeChallenge(string verifier)
        {
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(verifier));
                return Base64UrlEncode(hash);
            }
        }
        private static string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }
    }

        public class TokenResponse
    {
        public string access_token { get; set; } = "";
        public string id_token { get; set; } = "";
        public string refresh_token { get; set; } = "";
        public string token_type { get; set; } = "";
        public int expires_in { get; set; }
    }
}
