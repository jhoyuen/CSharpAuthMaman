using System.Collections.Generic;
using WinApp.Models;

namespace WinApp.Services
{
    public class UserService
    {
        public static string CurrentUser { get; set; }
        public static readonly Dictionary<string, string> s_users = new Dictionary<string, string>()
        {
            { "demo", "P@ssw0rd!" },
            { "alice", "Pass123$" }
        };

        public static readonly Dictionary<string, string> s_accessTokens = new Dictionary<string, string>();
        public static readonly Dictionary<string, string> s_refreshTokens = new Dictionary<string, string>();

        public User ValidateUser(string username, string password)
        {
            if (s_users.TryGetValue(username, out var storedPw) && storedPw == password)
            {
                return new User { Username = username };
            }
            return null;
        }

        public void StoreRefreshToken(string username, string refreshToken)
        {
            s_refreshTokens[username] = refreshToken;
        }

        public string GetRefreshToken(string username)
        {
            return s_refreshTokens.TryGetValue(username, out var token) ? token : null;
        }

        public void StoreAccessToken(string username, string accessToken)
        {
            s_accessTokens[username] = accessToken;
        }

        public string GetAccessToken(string username)
        {
            return s_accessTokens.TryGetValue(username, out var token) ? token : null;
        }
    }
}
