using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Vuln.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
    });

// Configure to use snake_case
builder.Services.Configure<JsonOptions>(options =>
{
    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
});

builder.Services.AddSwaggerGen(action =>
{
    action.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo { Title = "Vulnerability API", Version = "v1" });
});

// Register the VulnerabilityService for dependency injection
builder.Services.AddSingleton<VulnerabilityService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Vulnerability API V1");
        c.RoutePrefix = string.Empty; // Set Swagger UI at the app's root
    });
}

app.UseRouting();
app.UseAuthorization();
app.MapControllers();
app.UseHttpsRedirection();

app.Run();