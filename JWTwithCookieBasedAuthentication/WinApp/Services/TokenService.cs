using CefSharp.DevTools.IndexedDB;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WinApp.Models;

namespace WinApp.Services
{
    public class TokenService
    {
        private readonly string _key;
        private readonly string _issuer;
        private readonly Dictionary<string, string> _refreshTokens = new Dictionary<string, string>();

        public TokenService(string key, string issuer)
        {
            _key = key;
            _issuer = issuer;
        }

        public AuthResult GenerateTokens(string username)
        {
            var claims = new[] { 
                new Claim(ClaimTypes.Name, username)
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1), // Token expiration
                SigningCredentials = credentials,
                Issuer = _issuer,
                Audience = "Inception"
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            var accessToken = new JwtSecurityTokenHandler().WriteToken(token);
            var refreshToken = Guid.NewGuid().ToString();

            _refreshTokens[refreshToken] = username;

            return new AuthResult { AccessToken = accessToken, RefreshToken = refreshToken };
        }

        public string ValidateRefreshToken(string refreshToken)
        {
            return _refreshTokens.TryGetValue(refreshToken, out var username) ? username : null;
        }
    }
}
