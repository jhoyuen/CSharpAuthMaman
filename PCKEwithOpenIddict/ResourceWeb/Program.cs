using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

// Auth with JWT tokens from the IDP
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", opt =>
    {
        opt.Authority = "https://localhost:7199"; // your IDP
        opt.RequireHttpsMetadata = false;         // true in production
        opt.TokenValidationParameters.ValidateAudience = false;
        opt.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = ctx =>
            {
                Console.WriteLine($"Authentication failed: {ctx.Exception.Message}");
                return Task.CompletedTask;
            },
            OnChallenge = ctx =>
            {
                Console.WriteLine("OnChallenge error: " + ctx.ErrorDescription);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("ApiScope", policy =>
        policy.RequireAssertion(ctx => ctx.User.HasClaim("scope", "api")));
});

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
