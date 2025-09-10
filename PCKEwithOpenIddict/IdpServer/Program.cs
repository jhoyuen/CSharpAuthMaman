using IdpServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

// Add EF Core + Identity
builder.Services.AddDbContext<AuthDbContext>(opt =>
{
    opt.UseSqlite("Data Source=auth.db");
    opt.UseOpenIddict();
});

builder.Services
    .AddIdentity<AppUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// Cookie auth for login page
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
    });

// Add controllers (OpenIddict endpoints require controllers)
builder.Services.AddControllersWithViews();

// OpenIddict server
builder.Services.AddOpenIddict()
    .AddCore(opt => opt.UseEntityFrameworkCore().UseDbContext<AuthDbContext>())
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetUserinfoEndpointUris("/connect/userinfo");

        options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserinfoEndpointPassthrough()
            .DisableTransportSecurityRequirement(); // dev only
    })
    .AddValidation(opt =>
    {
        opt.UseLocalServer();
        opt.UseAspNetCore();
    });

var app = builder.Build();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var db = services.GetRequiredService<AuthDbContext>();
    db.Database.EnsureDeleted();
    db.Database.EnsureCreated();

    var appMgr = services.GetRequiredService<IOpenIddictApplicationManager>();
    var scopeMgr = services.GetRequiredService<IOpenIddictScopeManager>();
    var userMgr = services.GetRequiredService<UserManager<AppUser>>();

    // Seed OIDC Client
    if (await appMgr.FindByClientIdAsync("demo_client_pkce") == null)
    {
        await appMgr.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "demo_client_pkce",
            Type = ClientTypes.Public,
            ConsentType = ConsentTypes.Explicit,
            DisplayName = "Demo PKCE Client",
            RedirectUris = { new Uri("http://127.0.0.1:7890/") },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Prefixes.Scope + "openid",
                Permissions.Prefixes.Scope + "profile",
                Permissions.Prefixes.Scope + "email",
                Permissions.Prefixes.Scope + "api"
            },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange }
        });
    }

    // Seed Scopes
    foreach (var scopeName in new[] { "openid", "profile", "email", "api" })
    {
        if (await scopeMgr.FindByNameAsync(scopeName) == null)
        {
            await scopeMgr.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = scopeName,
                DisplayName = char.ToUpper(scopeName[0]) + scopeName.Substring(1) + " scope",
                Resources = { "demo_client_pkce" } // optional, restrict to certain clients
            });
        }
    }

    // --- Seed Users ---
    var demoUser = await userMgr.FindByNameAsync("demo");
    if (demoUser == null)
    {
        demoUser = new AppUser
        {
            UserName = "demo",
            Email = "demo@example.com",
            EmailConfirmed = true
        };
        var result = await userMgr.CreateAsync(demoUser, "P@ssw0rd!");
        if (!result.Succeeded)
        {
            throw new Exception("Failed to create demo user: " +
                string.Join(", ", result.Errors.Select(e => e.Description)));
        }
    }

    var aliceUser = await userMgr.FindByNameAsync("alice");
    if (aliceUser == null)
    {
        aliceUser = new AppUser
        {
            UserName = "alice",
            Email = "alice@example.com",
            EmailConfirmed = true
        };
        var result = await userMgr.CreateAsync(aliceUser, "Pass123$");
        if (!result.Succeeded)
        {
            throw new Exception("Failed to create alice user: " +
                string.Join(", ", result.Errors.Select(e => e.Description)));
        }
    }
}

app.Run();
