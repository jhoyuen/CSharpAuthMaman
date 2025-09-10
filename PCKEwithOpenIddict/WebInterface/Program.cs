using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/account/login"; // not used in this sample
    });

// We'll need OpenID Connect config for IdP validation
builder.Services.AddSingleton(provider =>
{
    var idpBase = "https://localhost:7199"; // IdP base URL
    var documentRetriever = new HttpDocumentRetriever { RequireHttps = false }; // dev only
    var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
        $"{idpBase}/.well-known/openid-configuration",
        new OpenIdConnectConfigurationRetriever(),
        documentRetriever);
    return configManager;
});

var app = builder.Build();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapDefaultControllerRoute();
app.Run();
