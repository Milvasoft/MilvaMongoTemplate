using Fody;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using System;
using System.Threading.Tasks;

namespace MilvaMongoTemplate.API.AppStartup
{
    /// <summary>
    /// The main entry point for the application.
    /// </summary>
    [ConfigureAwait(false)]
    public class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        /// <param name="args"></param>
        public static async Task Main(string[] args)
        {
            try
            {
                Log.Logger = new LoggerConfiguration()
                                 .WriteTo.Seq("http://seq:5341")
                                 .MinimumLevel.Information()
                                 .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
                                 .Enrich.WithProperty("AppName", "MilvaMongoTemplate API")
                                 .Enrich.WithProperty("Environment", "development")
                                 .CreateLogger();

                Log.Information("MilvaMongoTemplate API starting.");

                await CreateWebHostBuilder(args).Build().RunAsync();

            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "MilvaMongoTemplate API Host terminated unexpectedly");
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        /// <summary>
        /// Configures web api configurations.
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        public static IHostBuilder CreateWebHostBuilder(string[] args) =>
                  Host.CreateDefaultBuilder(args)
                  .ConfigureWebHostDefaults(webBuilder =>
                  {
                      webBuilder.UseUrls(/*"https://0.0.0.0:5001",*/"http://0.0.0.0:5000")
                                .UseWebRoot("wwwroot")
                                .UseStartup<Startup>()
                                .UseDefaultServiceProvider(options => options.ValidateScopes = false)
                                .ConfigureLogging(config => config.ClearProviders())
                                .UseSerilog();

                  });

    }
}
