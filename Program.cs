using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Vuln.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Load environment variables from .env file
DotNetEnv.Env.Load();

// Add environment variables
builder.Configuration.AddEnvironmentVariables();

// Register JwtSettings for dependency injection
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));

// Add authoriation services
builder.Services.AddAuthorization();

// Configure JWT authentication
// var key = Encoding.UTF8.GetBytes("oG~$Px,qs#@$'WOEi.tWzBRkWEiVC^lefvJ{1E(@V0#(uS.6n,");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(jwtOptions =>
    {
        JwtSettings _jwtSettings = new();
        builder.Configuration.GetSection("JwtSettings").Bind(_jwtSettings);
        Console.WriteLine(">>> SecretKey: " + _jwtSettings.SecretKey);
        
        jwtOptions.Authority = "https://vuln.notrev.net";
        jwtOptions.Audience = "https://vuln.notrev.net";
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

// Configure to use snake_case
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
builder.Services.AddSingleton<VulnerabilityService>();

// TODO: remove after debugging
// builder.Logging.AddDebug(); // Add debug logging
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Debug);

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
}

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.UseHttpsRedirection();

app.Run();