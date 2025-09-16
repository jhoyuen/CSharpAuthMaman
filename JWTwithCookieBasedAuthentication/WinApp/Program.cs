using CefSharp;
using CefSharp.WinForms;
using System;
using System.IO;
using System.Windows.Forms;

namespace WinApp
{
    internal static class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (!Cef.IsInitialized.GetValueOrDefault(false))
            {
                var settings = new CefSettings();

                string rootCachePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "JWTwithCookieBasedAuthenticationWinApp",
                    "CefRoot"
                );

                settings.RootCachePath = rootCachePath;

                settings.CachePath = Path.Combine(rootCachePath, "CefCache");

                // Optional: ignore SSL errors for dev
                settings.CefCommandLineArgs.Add("ignore-certificate-errors", "1");

                Cef.Initialize(settings);
            }

            using (var login = new LoginForm())
            {
                var result = login.ShowDialog();

                if (result == DialogResult.OK)
                {
                    // Only show MainForm if LoginForm succeeded
                    Application.Run(new MainForm());
                }
                else
                {
                    // Exit app if login fails/cancelled
                    Application.Exit();
                }
            }
        }
    }
}