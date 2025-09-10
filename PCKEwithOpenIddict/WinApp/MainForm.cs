using System.Windows.Forms;

namespace WinApp
{
    public partial class MainForm : Form
    {
        private Button btnLogin;
        public MainForm()
        {
            btnLogin = new Button { Text = "Login & Open Web Interface", Dock = DockStyle.Top };
            btnLogin.Click += async (s, e) =>
            {
                var flow = new NativeAuthFlow();
                await flow.PerformLoginAndOpenWebBAsync(this);
            };
            Controls.Add(btnLogin);
            Width = 1000; Height = 700;
        }
    }
}
