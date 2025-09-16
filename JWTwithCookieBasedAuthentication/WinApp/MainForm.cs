using CefSharp;
using CefSharp.WinForms;
using System;
using System.IO;
using System.Net.Http;
using System.Runtime;
using System.Windows.Forms;
using WinApp.Services;

namespace WinApp
{
    public partial class MainForm : Form
    {
        private Button btnLogin;
        private ChromiumWebBrowser browser;

        public MainForm()
        {
            btnLogin = new Button { Text = "Load Web Interface", Dock = DockStyle.Top };
            btnLogin.Click += BtnLogin_Click;
            Controls.Add(btnLogin);

            Width = 1000;
            Height = 700;
        }

        private void BtnLogin_Click(object sender, EventArgs e)
        {
            if (browser != null) return; // prevent multiple

            string accessToken = UserService.s_accessTokens[UserService.CurrentUser]
                                 ?? throw new Exception("No token available");
            string webUrl = $"https://localhost:7081/account/externallogin?token={Uri.EscapeDataString(accessToken).Trim()}";

            browser = new ChromiumWebBrowser("about:blank")
            {
                Dock = DockStyle.Fill
            };

            browser.IsBrowserInitializedChanged += (s, args) =>
            {
                if (browser.IsBrowserInitialized)
                {
                    browser.Load(webUrl);
                }
            };

            Controls.Add(browser);
            browser.BringToFront();
        }
    }
}
