using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MilvaMongoTemplate.API.Helpers;
using MilvaMongoTemplate.API.Helpers.Swagger;
using MilvaMongoTemplate.API.Services.Abstract;
using MilvaMongoTemplate.API.Services.Concrete;
using Milvasoft.Caching.Redis;
using Milvasoft.Core.Abstractions;
using Milvasoft.DataAccess.MongoDB.Utils;
using Milvasoft.DataAccess.MongoDB.Utils.Settings;
using Milvasoft.Encryption.Abstract;
using Milvasoft.Encryption.Concrete;
using Milvasoft.FileOperations;
using Milvasoft.FileOperations.Abstract;
using Milvasoft.FileOperations.Concrete;
using Milvasoft.Identity.Abstract;
using Milvasoft.Identity.Builder;
using Milvasoft.Identity.Concrete;
using Milvasoft.Identity.Concrete.Options;
using Milvasoft.Mail;
using Newtonsoft.Json;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;

namespace MilvaMongoTemplate.API.AppStartup;

/// <summary>
/// Service collection helpers.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds MVC services to the specified Microsoft.Extensions.DependencyInjection.IServiceCollection.
    /// </summary>
    /// <param name="services"></param>
    public static void AddControllers(this IServiceCollection services)
    {
        services.AddControllers(opt =>
        {
            //opt.ModelBinderProviders.Insert(0, new JsonModelBinderProvider());
            opt.SuppressAsyncSuffixInActionNames = false;
            opt.EnableEndpointRouting = true;
        }).AddNewtonsoftJson(opt =>
        {
            opt.SerializerSettings.Converters.Add(new ObjectIdJsonConverter());
            opt.SerializerSettings.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;
            opt.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;

        }).ConfigureApiBehaviorOptions(options =>
          {
              options.InvalidModelStateResponseFactory = actionContext =>
              {
                  return CommonHelper.CustomErrorResponse(actionContext);
              };
          }).AddDataAnnotationsLocalization();
    }

    /// <summary>
    /// Configured cors policies.
    /// </summary>
    /// <param name="services"></param>
    public static void AddCors(this IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("ApiCorsPolicy", builder =>
            {
                builder.AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader()
                .Build();
            });

        });
    }

    /// <summary>
    /// Configures AspNetCore.Identity.Mongo and JWT.
    /// </summary>
    /// <param name="services"></param>
    public static void AddIdentity(this IServiceCollection services)
    {
        static void identityOptions(MilvaIdentityOptions setupAction)
        {
            //Kullanıcı locklama süresi
            setupAction.Lockout.DefaultLockoutTimeSpan = new TimeSpan(3, 1, 0);//buradaki 3 saaat ekleme veri tabanı saati yanlış olduğundan dolayı // 1 ise 1 dakka kitleniyor
            setupAction.Lockout.MaxFailedAccessAttempts = 5;//Başarısız deneme sayısı
            setupAction.User.RequireUniqueEmail = false;
            setupAction.Password.RequireDigit = false;
            setupAction.Password.RequiredLength = 1;
            setupAction.Password.RequireLowercase = false;
            setupAction.Password.RequireNonAlphanumeric = false;
            setupAction.Password.RequireUppercase = false;
            setupAction.User.AllowedUserNameCharacters = "abcçdefghiıjklmnoöpqrsştuüvwxyzABCÇDEFGHIİJKLMNOÖPQRSŞTUÜVWXYZ0123456789-._";
        }

        services.AddMilvaIdentity<MilvaMongoTemplateUser, ObjectId>()
                .WithOptions(identityOptions)
                .WithUserManager<MilvaUserManager<MilvaMongoTemplateUser, ObjectId>>();
    }

    /// <summary>
    /// Configures JWT Token Authentication.
    /// </summary>
    /// <param name="services"></param>
    public static void AddJwtBearer(this IServiceCollection services)
    {
        var tokenManagement = GlobalConstant.Configurations.Tokens.First(i => i.Key == StringKey.Public);

        services.AddSingleton<ITokenManagement>(tokenManagement);

        var tokenValidationParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(tokenManagement.Secret)),
            ValidateIssuer = false,
            ValidIssuer = string.Empty,
            ValidateAudience = false,
            ValidAudience = string.Empty,
            ValidateLifetime = false,
            RequireExpirationTime = false
        };

        services.AddSingleton(tokenValidationParams);

        services.AddAuthorization();

        services.AddAuthentication(opt =>
        {
            opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(jwtOpt =>
        {
            jwtOpt.RequireHttpsMetadata = false;
            jwtOpt.SaveToken = true;
            jwtOpt.TokenValidationParameters = tokenValidationParams;
        });
    }

    /// <summary>
    /// Configures DI.
    /// </summary>
    /// <param name="services"></param>
    public static void ConfigureDependencyInjection(this IServiceCollection services)
    {
        services.AddSingleton<SharedResource>();
        services.AddScoped<IJsonOperations, JsonOperations>();
        services.AddSingleton<IMilvaLogger, MilvaMongoTemplateLogger>();
        services.AddScoped<IApplicationBuilder, ApplicationBuilder>();
        services.AddTransient(typeof(Lazy<>), typeof(MilvaLazy<>));
        services.AddHttpClient();
        services.AddHttpContextAccessor();
        services.AddSingleton<IMilvaResource, SharedResource>();

        GlobalConstant.MainMail = GlobalConstant.Configurations.Mails.First(i => i.Key == StringKey.MilvaTemplateMail);

        services.AddSingleton<IMilvaMailSender>(new MilvaMailSender(GlobalConstant.MainMail.Sender,
                                                                    new NetworkCredential(GlobalConstant.MainMail.Sender, GlobalConstant.MainMail.SenderPass),
                                                                    GlobalConstant.MainMail.SmtpPort,
                                                                    GlobalConstant.MainMail.SmtpHost,
                                                                    true));

        services.AddScoped<IMilvaEncryptionProvider>((_) => new MilvaEncryptionProvider(GlobalConstant.MilvaMongoTemplateKey));

        #region Services

        services.AddScoped<IAccountService, AccountService>();

        #endregion

        //Validation hatalarını optimize ettiğimiz için .net tarafından hata fırlatılmasını engelliyor.
        services.Configure<ApiBehaviorOptions>(options => options.SuppressModelStateInvalidFilter = true);
    }

    /// <summary>
    /// Configures database connection.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="jsonOperations"></param>
    public static void ConfigureDatabase(this IServiceCollection services, IJsonOperations jsonOperations)
    {
        var mongoSettings = jsonOperations.GetCryptedContentAsync<MongoDbSettings>($"connectionstring.{Startup.WebHostEnvironment.EnvironmentName}.json").Result;

        services.AddMilvaMongoHelper(opt =>
        {
            opt.AddTenantIdSupport = true;
            opt.MongoClientSettings = new MongoClientSettings
            {
                MinConnectionPoolSize = 400,
                MaxConnectionPoolSize = 600,
                Server = new MongoServerAddress(Startup.WebHostEnvironment.EnvironmentName == "Production" ? "mongodb" : "localhost")
            };
            opt.DatabaseName = mongoSettings.DatabaseName;
            opt.EncryptionKey = GlobalConstant.MilvaMongoTemplateKey;
            opt.UseUtcForDateTimes = true;
        });

        services.AddScoped(typeof(IBaseRepository<>), typeof(BaseRepository<>));
    }

    /// <summary>
    /// Configures API versioning.
    /// </summary>
    /// <param name="services"></param>
    public static void AddVersioning(this IServiceCollection services)
    {
        services.AddApiVersioning(config =>
        {
            // Specify the default API Version
            config.DefaultApiVersion = new ApiVersion(1, 0);
            // If the client hasn't specified the API version in the request, use the default API version number 
            config.AssumeDefaultVersionWhenUnspecified = true;
            // Advertise the API versions supported for the particular endpoint
            config.ReportApiVersions = true;
        });
    }

    /// <summary>
    /// Configures API versioning.
    /// </summary>
    /// <param name="services"></param>
    public static IServiceCollection AddMilvaRedisCaching(this IServiceCollection services)
    {
        var connectionString = Startup.WebHostEnvironment.EnvironmentName == "Development" ? "127.0.0.1:6379" : "redis";

        var cacheOptions = new RedisCacheServiceOptions(connectionString);

        cacheOptions.ConfigurationOptions.AbortOnConnectFail = false;
        cacheOptions.ConfigurationOptions.ConnectTimeout = 10000;
        cacheOptions.ConfigurationOptions.SyncTimeout = 10000;
        cacheOptions.ConfigurationOptions.ConnectRetry = 1;
        cacheOptions.Lifetime = ServiceLifetime.Singleton;
        //cacheOptions.ConfigurationOptions.Ssl = true;
        //cacheOptions.ConfigurationOptions.SslProtocols = SslProtocols.Tls12;

        return services.AddMilvaRedisCaching(cacheOptions);
    }

    /// <summary>
    /// Configures Swagger documentation.
    /// </summary>
    /// <param name="services"></param>
    public static void AddSwagger(this IServiceCollection services)
    {
        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1.0", new OpenApiInfo
            {
                Version = "v1.0",
                Title = "MilvaMongoTemplate API",
                Description = "MilvaMongoTemplate API",
                TermsOfService = new Uri("https://milvasoft.com"),
                Contact = new OpenApiContact { Name = "Milvasoft Yazılım", Email = "info@milvasoft.com", Url = new Uri("https://milvasoft.com") },
                License = new OpenApiLicense { Name = "MIT", Url = new Uri("https://opensource.org/licenses/MIT") }
            });


            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                In = ParameterLocation.Header,
                Description = "Please insert JWT with Bearer into field",
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey
            });

            options.AddSecurityRequirement(new OpenApiSecurityRequirement {
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

            var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            options.IncludeXmlComments(xmlPath);
            options.SchemaFilter<CustomAttributeSchemaFilter>();
            options.OperationFilter<CustomAttributeOperationFilter>();
            options.SchemaFilter<SwaggerExcludeFilter>();
            options.OperationFilter<RequestHeaderFilter>();
            options.DocumentFilter<ReplaceVersionWithExactValueInPathFilter>();
        });
    }

    /// <summary>
    /// Adds json operations to service collection.
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IJsonOperations AddJsonOperations(this IServiceCollection services)
    {
        var jsonOperationsConfig = new JsonOperationsConfig
        {
            EncryptionKey = GlobalConstant.MilvaMongoTemplateKey,
            BasePath = GlobalConstant.JsonFilesPath
        };

        services.AddJsonOperations(options: opt =>
        {
            opt.BasePath = jsonOperationsConfig.BasePath;
            opt.EncryptionKey = jsonOperationsConfig.EncryptionKey;
        });

        return new JsonOperations(jsonOperationsConfig);
    }

}
