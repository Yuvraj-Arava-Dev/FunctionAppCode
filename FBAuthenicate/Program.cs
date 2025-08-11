using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Azure.Messaging.EventHubs.Producer;

var builder = FunctionsApplication.CreateBuilder(args);

builder.ConfigureFunctionsWebApplication();

builder.Services
    .AddApplicationInsightsTelemetryWorkerService()
    .ConfigureFunctionsApplicationInsights()
    .AddMemoryCache();

// Register EventHubProducerClient using configuration
builder.Services.AddSingleton<EventHubProducerClient>(sp =>
{
    var cfg = sp.GetRequiredService<IConfiguration>();
    var connectionString = cfg["EventHubConnectionString"];
    var eventHubName = cfg["EventHubName"];
    return new EventHubProducerClient(connectionString, eventHubName);
});

builder.Build().Run();
