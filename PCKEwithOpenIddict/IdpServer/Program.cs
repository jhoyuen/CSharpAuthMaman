using System.Security.Claims;
using IdpServer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

// Database + Identity
builder.Services.AddDbContext<AuthDbContext>(opt =>
{
    opt.UseSqlite("Data Source=auth.db");
    opt.UseOpenIddict();
});
builder.Services
    .AddIdentity<AppUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// Authentication cookies for the IDP session
builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.LoginPath = "/account/login";
    opt.LogoutPath = "/account/logout";
});

// OpenIddict setup
builder.Services.AddOpenIddict()
    .AddCore(opt => opt.UseEntityFrameworkCore().UseDbContext<AuthDbContext>())
    .AddServer(opt =>
    {
        opt.SetAuthorizationEndpointUris("/connect/authorize")
           .SetTokenEndpointUris("/connect/token")
           .SetUserinfoEndpointUris("/connect/userinfo");

        opt.AllowAuthorizationCodeFlow();
        opt.RequireProofKeyForCodeExchange();

        opt.RegisterScopes(Scopes.OpenId, Scopes.Profile, Scopes.Email, "api");

        //opt.UseJsonWebTokens();
        opt.AddDevelopmentEncryptionCertificate()
           .AddDevelopmentSigningCertificate();

        opt.UseAspNetCore()
           .EnableAuthorizationEndpointPassthrough()
           .EnableTokenEndpointPassthrough()
           .EnableUserinfoEndpointPassthrough();
    });

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Seed demo user + client
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var db = services.GetRequiredService<AuthDbContext>();
    db.Database.EnsureCreated();

    var userMgr = services.GetRequiredService<UserManager<AppUser>>();
    var appMgr = services.GetRequiredService<IOpenIddictApplicationManager>();

    var demoUser = await userMgr.FindByNameAsync("demo");
    if (demoUser is null)
    {
        demoUser = new AppUser { UserName = "demo", Email = "demo@example.com" };
        await userMgr.CreateAsync(demoUser, "P@ssw0rd!");
        await userMgr.AddClaimAsync(demoUser, new Claim(ClaimTypes.Name, "Demo User"));
    }

    var clientId = "demo_client_pkce";
    if (await appMgr.FindByClientIdAsync(clientId) is null)
    {
        await appMgr.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            Type = ClientTypes.Public,
            ConsentType = ConsentTypes.Explicit,
            DisplayName = "Demo PKCE Client",
            RedirectUris = { new Uri("https://127.0.0.1:7202/callback") },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Email,
                Permissions.Prefixes.Scope + "api"
            },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange }
        });
    }
}

app.UseRouting();

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.MapGet("/", () => "IDP running. See /.well-known/openid-configuration");

app.Run();
