﻿#region Using Directives
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Localization;
using MilvaMongoTemplate.API.Helpers.Models;
using MilvaMongoTemplate.API.Middlewares;
using Milvasoft.Middlewares;
using System.IO;
#endregion

namespace MilvaMongoTemplate.API.AppStartup;

/*

 TODO What to do in step by step;
    - Check the GlobalConstants.cs for unnecessary variables for this project.
    - Check the HelperExtensions.cs for unnecessary extensions for this project.
    - Check services and middlewares in this file.
    - Change the running port on IIS of the api in launchsetting.json.
    - Check the sample controller and service. (Account)
    - Check Migrations folder and add your necessary methods into classes.
    - Decrypt connectionstring.*.json files and change connection string.
    - Decrypt configurations.json file and change api configurations.
    - Enter mailsender password in ServiceCollectionExtensions.cs.
    - Change encryption keys.
    - Lastly and hardest, remove this comment block :)

 */

/// <summary>
/// Application configuration.
/// </summary>
[ConfigureAwait(false)]
public class Startup
{
    #region Fields

    private static IServiceCollection _serviceCollection;

    #endregion

    #region Properties

    /// <summary> WebHostEnvironment value. </summary>
    public static IWebHostEnvironment WebHostEnvironment { get; set; }

    /// <summary>
    /// For access shared resources.
    /// </summary>
    public static IStringLocalizer<SharedResource> SharedStringLocalizer { get; set; }

    #endregion

    /// <summary>
    /// Initializes new instance of <see cref="Startup"/>.
    /// </summary>
    /// <param name="env"></param>
    public Startup(IWebHostEnvironment env)
    {
        WebHostEnvironment = env;
    }

    /// <summary>
    /// This method gets called by the runtime. Use this method to add services to the container.
    /// </summary>
    /// <param name="services"></param>
    public void ConfigureServices(IServiceCollection services)
    {
        //Will be remove production.
        //StartupConfiguration.EncryptFile().Wait();
        //StartupConfiguration.DecryptFile().Wait();

        _serviceCollection = services;

        Console.Out.WriteAppInfo("Service collection registration starting...");

        var jsonOperations = services.AddJsonOperations();

        GlobalConstant.Configurations = jsonOperations.GetCryptedContentAsync<Configurations>(Path.Combine(GlobalConstant.JsonFilesPath,
                                                                                                           "configurations.json")).Result;

        services.AddLocalization(options => options.ResourcesPath = "Resources");

        //services.AddMilvaRedisCaching();

        services.AddControllers();

        services.AddVersioning();

        services.AddCors();

        services.ConfigureDependencyInjection();

        services.ConfigureDatabase(jsonOperations);

        services.AddIdentity();

        services.AddJwtBearer();

        services.AddSwagger();

        Console.Out.WriteAppInfo("All services registered to service collection.");
    }

    /// <summary>
    /// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    /// </summary>
    /// <param name="app"></param>
    /// <param name="sharedStringLocalizer"></param>
    public void Configure(IApplicationBuilder app, IStringLocalizer<SharedResource> sharedStringLocalizer)
    {
        //Initializes string localizer 
        SharedStringLocalizer = sharedStringLocalizer;

        if (WebHostEnvironment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();

            app.UseMilvaResponseTimeCalculator();
        }

        app.UseRequestLocalization();

        app.UseMilvaMongoTemplateExceptionHandler();

        app.UseStaticFiles();

        app.UseRouting();

        app.UseCors("ApiCorsPolicy");

        app.UseAuthentication();

        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllerRoute("Default", "{controller=Account}/{action=Get}/{id?}");
        });

        app.UseSwagger();

        app.ConfigureAppStartupAsync(_serviceCollection).Wait();

        Console.Out.WriteAppInfo($"Hosting environment : {WebHostEnvironment.EnvironmentName}");
        Console.Out.WriteAppInfo($"Application started. Press Ctrl+C to shut down.");
    }
}
