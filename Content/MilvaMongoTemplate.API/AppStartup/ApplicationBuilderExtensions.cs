﻿using Fody;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.FileProviders;
using MilvaMongoTemplate.API.Helpers;
using Swashbuckle.AspNetCore.SwaggerUI;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace MilvaMongoTemplate.API.AppStartup
{
    /// <summary>
    /// Application builder extension helpers.
    /// </summary>
    [ConfigureAwait(false)]
    public static class ApplicationBuilderExtensions
    {
        /// <summary>
        /// Static file definitions.
        /// </summary>
        /// <param name="app"></param>
        /// <returns></returns>
        public static void UseDirectoryBrowser(this IApplicationBuilder app)
        {
            app.UseDirectoryBrowser(new DirectoryBrowserOptions()
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), @"wwwroot", "Media Library")),
                RequestPath = new PathString($"/{GlobalConstants.RoutePrefix}/MediaLibrary")
            });
        }

        /// <summary>
        /// Static file definitions
        /// </summary>
        /// <param name="app"></param>
        /// <returns></returns>
        public static void UseStaticFiles(this IApplicationBuilder app)
        {
            app.UseStaticFiles($"/{GlobalConstants.RoutePrefix}");
            app.UseStaticFiles(new StaticFileOptions()
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "StaticFiles")),
                RequestPath = new PathString($"/{GlobalConstants.RoutePrefix}/admin")
            });
            app.UseStaticFiles(new StaticFileOptions()
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), @"wwwroot", @"Media Library/Image Library")),
                RequestPath = new PathString($"/{GlobalConstants.RoutePrefix}/ImageLibrary")
            });
            app.UseStaticFiles(new StaticFileOptions()
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), @"wwwroot", @"Media Library/Video Library")),
                RequestPath = new PathString($"/{GlobalConstants.RoutePrefix}/VideoLibrary")
            });
        }

        /// <summary>
        /// <para> Adds a Microsoft.AspNetCore.Routing.EndpointMiddleware middleware to the specified
        ///        Microsoft.AspNetCore.Builder.IApplicationBuilder with the Microsoft.AspNetCore.Routing.EndpointDataSource
        ///        instances built from configured Microsoft.AspNetCore.Routing.IEndpointRouteBuilder.
        ///        The Microsoft.AspNetCore.Routing.EndpointMiddleware will execute the Microsoft.AspNetCore.Http.Endpoint
        ///        associated with the current request. </para>
        /// </summary>
        /// <param name="app"> The Microsoft.AspNetCore.Builder.IApplicationBuilder to add the middleware to. </param>
        /// <returns>  A reference to this instance after the operation has completed. </returns>
        public static void UseEndpoints(this IApplicationBuilder app)
        {
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute("Default", "{controller=Product}/{action=product}/{id?}");
            });
        }

        /// <summary>
        /// Static file definitions.
        /// </summary>
        /// <param name="app"></param>
        /// <returns></returns>
        public static void UseSwagger(this IApplicationBuilder app)
        {
            app.UseSwagger(c =>
            {
                c.SerializeAsV2 = true;
                c.RouteTemplate = GlobalConstants.RoutePrefix + "/docs/{documentName}/docs.json";
            }).UseSwaggerUI(c =>
            {
                c.DefaultModelExpandDepth(-1);
                c.DefaultModelsExpandDepth(1);
                c.DefaultModelRendering(ModelRendering.Model);
                c.DocExpansion(DocExpansion.None);
                c.RoutePrefix = $"{GlobalConstants.RoutePrefix}/documentation";
                c.SwaggerEndpoint($"/{GlobalConstants.RoutePrefix}/docs/v1.0/docs.json", "MilvaMongoTemplate API v1.0");
                c.SwaggerEndpoint($"/{GlobalConstants.RoutePrefix}/docs/v1.1/docs.json", "MilvaMongoTemplate API v1.1");
                c.InjectStylesheet($"/{GlobalConstants.RoutePrefix}/swagger-ui/custom.css");
                c.InjectJavascript($"/{GlobalConstants.RoutePrefix}/swagger-ui/custom.js");
            });
        }

        /// <summary>
        /// Adds the required middleware to use the localization. Configures the options before add.
        /// </summary>
        /// <param name="app"></param>
        /// <returns></returns>
        public static IApplicationBuilder UseRequestLocalization(this IApplicationBuilder app)
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");

            var supportedCultures = new List<CultureInfo>
            {
                new CultureInfo("tr-TR"),
                new CultureInfo("en-US")
            };
            var options = new RequestLocalizationOptions
            {
                DefaultRequestCulture = new RequestCulture("tr-TR"),
                SupportedCultures = supportedCultures,
                SupportedUICultures = supportedCultures
            };

            return app.UseRequestLocalization(options);
        }
    }

}