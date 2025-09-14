using Duende.IdentityModel.OidcClient.Browser;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace WinAppUsingIdpLoginForm
{
    class SystemBrowser : IBrowser
    {
        private readonly int _port;

        public SystemBrowser(int port)
        {
            _port = port;
        }

        public async Task<BrowserResult> InvokeAsync(BrowserOptions options, System.Threading.CancellationToken cancellationToken = default)
        {
            using (var listener = new HttpListener())
            {
                listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
                listener.Start();

                Process.Start(new ProcessStartInfo
                {
                    FileName = options.StartUrl,
                    UseShellExecute = true
                });

                var context = await listener.GetContextAsync();
                var response = context.Response;
                string responseString = "<html><head><meta http-equiv='refresh' content='10;url=https://localhost'></head><body>Please return to the app.</body></html>";
                var buffer = Encoding.UTF8.GetBytes(responseString);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.OutputStream.Close();

                return new BrowserResult
                {
                    Response = context.Request.Url.ToString(),
                    ResultType = BrowserResultType.Success
                };
            }
        }
    }
}
