using System;
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