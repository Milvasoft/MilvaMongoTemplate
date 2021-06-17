﻿#region Using Directives
using Fody;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Localization;
using MilvaMongoTemplate.API.Helpers;
using MilvaMongoTemplate.API.Middlewares;
using MilvaMongoTemplate.Data.Utils;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers.FileOperations.Abstract;
using Milvasoft.Helpers.FileOperations.Concrete;
using System.Threading.Tasks;
#endregion

namespace MilvaMongoTemplate.API.AppStartup
{
    /*
     
     TODO What to do in step by step;
        - Check the GlobalConstants.cs for unnecessary variables for this project.
        - Check the HelperExtensions.cs for unnecessary extensions for this project.
        - Check services and middlewares in this file.
        - Change the running port on IIS of the api in launchsetting.json.
        - Check the sample controller and service. (Account)
        - Check Migrations folder and add your necessary methods into classes.
        - Decrypt conncetionstring.*.json files and change connection string.
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

        /// <summary> Configuration value. </summary>
        private readonly IJsonOperations _jsonOperations;

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
            _jsonOperations = new JsonOperations();
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

            StartupConfiguration.CheckPublicFiles();

            services.AddLocalization(options => options.ResourcesPath = "Resources");

            //services.AddMilvaRedisCaching();

            services.AddControllers();

            services.AddVersioning();

            services.AddCors();

            services.ConfigureDependencyInjection();

            services.ConfigureDatabase(_jsonOperations);

            services.AddIdentity();

            services.AddJwtBearer(_jsonOperations);

            services.AddSwagger();

            StartupConfiguration.FillStringBlacklistAsync(_jsonOperations).Wait();

            services.AddSingleton(GlobalConstants.StringBlacklist);
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

            ConfigureAppStartupAsync(app).Wait();
        }


        /// <summary>
        /// This method provides async configure process which configure() called by the runtime.
        /// </summary>
        /// <param name="app"></param>
        /// <returns></returns>
        public async Task ConfigureAppStartupAsync(IApplicationBuilder app)
        {
            await app.ResetDataAsync().ConfigureAwait(false);

            await StartupConfiguration.FillAllowedFileExtensionsAsync(_jsonOperations);

            await StartupConfiguration.FillStringBlacklistAsync(_jsonOperations);
        }

    }
}