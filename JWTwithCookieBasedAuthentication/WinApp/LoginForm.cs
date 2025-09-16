using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;
using WinApp.Models;
using WinApp.Services;

namespace WinApp
{
    public partial class LoginForm : Form
    {
        public LoginForm()
        {
            InitializeComponent();
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

            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private bool ValidateLocalLogin(string username, string password)
        {
            var userService = new UserService();
            var tokenService = new TokenService("super_secret_dev_key_123456789012345", "JwtAuthIssuer");

            var user = userService.ValidateUser(username, password);
            if (user == null)
                return false;

            var authResult = tokenService.GenerateTokens(user.Username);
            UserService.CurrentUser = user.Username;
            userService.StoreAccessToken(user.Username, authResult.AccessToken);
            userService.StoreRefreshToken(user.Username, authResult.RefreshToken);

            return true;
        }
    }
}
