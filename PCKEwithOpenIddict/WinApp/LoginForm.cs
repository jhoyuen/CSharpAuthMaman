using Duende.IdentityModel.Client;
using Duende.IdentityModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Collections.Specialized;

namespace WinApp
{
    public partial class LoginForm : Form
    {
        private ICollection<KeyValuePair<string, string>> _dummyLogins =
            new List<KeyValuePair<string, string>>();

        public LoginForm()
        {
            InitializeComponent();

            _dummyLogins.Add(new KeyValuePair<string, string>("demo", "P@ssw0rd!"));
            _dummyLogins.Add(new KeyValuePair<string, string>("alice", "Pass123$"));
        }

        private async void btnLogin_Click(object sender, EventArgs e)
        {

            var username = txtUsername.Text;
            var password = txtPassword.Text;

            // Step 1: validate locally (pseudo code: replace with your enterprise logic)
            if (!ValidateLocalLogin(username, password))
            {
                MessageBox.Show("Invalid credentials.");
                return;
            }

            MessageBox.Show($"Login succeeded!");
            // TODO: store tokens securely for later API calls

            NativeAuthFlow.User = username;
            NativeAuthFlow.Pass = password;
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private bool ValidateLocalLogin(string username, string password)
        {
            // Replace this with your real local auth logic
            return _dummyLogins.Any(kv => kv.Key == username && kv.Value == password);
        }
    }
}
