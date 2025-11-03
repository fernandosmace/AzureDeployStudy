using Azure.Identity;
using AzureDeployStudy.Components;
using AzureDeployStudy.Components.Account;
using AzureDeployStudy.Data;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AzureDeployStudy
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            string? keyVaultUri = builder.Configuration["KeyVaultUri"];

            if (!string.IsNullOrEmpty(keyVaultUri) && Uri.TryCreate(keyVaultUri, UriKind.Absolute, out var keyVaultEndpoint))
            {
                // Este código SÓ SERÁ EXECUTADO se o KeyVaultUri for encontrado
                // (no appsettings.json, variáveis de ambiente, etc.) E for uma URI válida.

                // Em ambientes de desenvolvimento/CI, você pode adicionar uma checagem de ambiente 
                // para evitar erros de DefaultAzureCredential, mas essa checagem já deve ajudar.

                Console.WriteLine($"Key Vault URI found. Loading secrets from: {keyVaultUri}");

                try
                {
                    builder.Configuration.AddAzureKeyVault(keyVaultEndpoint, new DefaultAzureCredential());
                }
                catch (Exception ex)
                {
                    // Capturar falhas de autenticação (comum em CI/CD ou local)
                    Console.WriteLine($"ERRO ao carregar Key Vault. Continuando sem secrets. Erro: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("Key Vault URI not found or invalid. Skipping Azure Key Vault configuration.");
            }

            // Add services to the container.
            builder.Services.AddRazorComponents()
                .AddInteractiveServerComponents();

            builder.Services.AddCascadingAuthenticationState();
            builder.Services.AddScoped<IdentityUserAccessor>();
            builder.Services.AddScoped<IdentityRedirectManager>();
            builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

            builder.Services.AddAuthentication(options =>
                {
                    options.DefaultScheme = IdentityConstants.ApplicationScheme;
                    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
                })
                .AddIdentityCookies();

            var connectionString = Environment.GetEnvironmentVariable("CustomerConnectionString");
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(
                    connectionString,
                    sqlOptions => sqlOptions.EnableRetryOnFailure(
                        maxRetryCount: 5,
                        maxRetryDelay: TimeSpan.FromSeconds(10),
                        errorNumbersToAdd: null
                    )
                );
            });
            builder.Services.AddDatabaseDeveloperPageExceptionFilter();

            builder.Services.AddIdentityCore<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddSignInManager()
                .AddDefaultTokenProviders();

            builder.Services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseStaticFiles();
            app.UseAntiforgery();

            app.MapRazorComponents<App>()
                .AddInteractiveServerRenderMode();

            // Add additional endpoints required by the Identity /Account Razor components.
            app.MapAdditionalIdentityEndpoints();

            app.Run();
        }
    }
}
