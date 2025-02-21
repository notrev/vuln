using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using Vuln.Models;
using Vuln.Services;
using Vuln.Data;

var builder = WebApplication.CreateBuilder(args);

// Load environment variables from .env file
DotNetEnv.Env.Load();

// Add environment variables
builder.Configuration.AddEnvironmentVariables();

// Register JwtSettings for dependency injection
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));

// Register the DbContext
string connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? "";
builder.Services.AddDbContext<ApplicationDbContext>(options => 
    options.UseNpgsql(connectionString));

// For Identity management
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure JWT authentication
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(jwtOptions =>
    {
        JwtSettings _jwtSettings = new();
        builder.Configuration.GetSection("JwtSettings").Bind(_jwtSettings);

        jwtOptions.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey)),
            ValidAudiences = [_jwtSettings.Audience],
            ValidIssuers = [_jwtSettings.Issuer]
        };
    });

builder.Services.AddOpenApi();
builder.Services.AddControllers();

builder.Services.Configure<JsonOptions>(options =>
{
    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
});

// Setup SwaggerGen
builder.Services.AddSwaggerGen(setup =>
{
    setup.SwaggerDoc("v1", new OpenApiInfo { Title = "Vulnerability API", Version = "v1" });

    // Add security definition for JWT Bearer
    setup.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Authorization token in the format **Bearer {your token}**",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });

    // Add security requirement
    setup.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Register the VulnerabilityService for dependency injection
builder.Services.AddScoped<VulnerabilityService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI(setup =>
    {
        setup.SwaggerEndpoint("/swagger/v1/swagger.json", "Vulnerability API V1");
        setup.RoutePrefix = "docs";
    });
    await DbSeeder.SeedVulnerabilities(app);
}

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.UseHttpsRedirection();
await DbSeeder.SeedRolesAndUsers(app, app.Environment.IsDevelopment());

app.Run();