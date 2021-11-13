using AspNetCore.Identity.Mongo;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MilvaMongoTemplate.API.Helpers;
using MilvaMongoTemplate.API.Helpers.Constants;
using MilvaMongoTemplate.API.Helpers.Models;
using MilvaMongoTemplate.API.Helpers.Swagger;
using MilvaMongoTemplate.API.Services.Abstract;
using MilvaMongoTemplate.API.Services.Concrete;
using MilvaMongoTemplate.Data.Utils;
using MilvaMongoTemplate.Entity.Collections;
using MilvaMongoTemplate.Entity.Utils;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers;
using Milvasoft.Helpers.Caching;
using Milvasoft.Helpers.DataAccess.MongoDB.Abstract;
using Milvasoft.Helpers.DataAccess.MongoDB.Concrete;
using Milvasoft.Helpers.DataAccess.MongoDB.Utils;
using Milvasoft.Helpers.DependencyInjection;
using Milvasoft.Helpers.Encryption.Concrete;
using Milvasoft.Helpers.FileOperations;
using Milvasoft.Helpers.FileOperations.Abstract;
using Milvasoft.Helpers.FileOperations.Concrete;
using Milvasoft.Helpers.Identity.Abstract;
using Milvasoft.Helpers.Identity.Concrete;
using Milvasoft.Helpers.Mail;
using Milvasoft.Helpers.Models.Response;
using Milvasoft.Helpers.Utils;
using MongoDB.Bson;
using Newtonsoft.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

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
        Action<IdentityOptions> identityOptions = setupAction =>
        {
            //Kullanıcı locklama süresi
            setupAction.Lockout.DefaultLockoutTimeSpan = new TimeSpan(0, 10, 0);
            setupAction.Lockout.MaxFailedAccessAttempts = 5;
            setupAction.User.RequireUniqueEmail = true;
            setupAction.Password.RequireDigit = false;
            setupAction.Password.RequiredLength = 1;
            setupAction.Password.RequireLowercase = false;
            setupAction.Password.RequireNonAlphanumeric = false;
            setupAction.Password.RequireUppercase = false;
            setupAction.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";
            //setupAction.Stores.ProtectPersonalData = true;
            //setupAction.Stores.MaxLengthForKeys = 128;
        };

        var mongoSettings = services.BuildServiceProvider().GetRequiredService<IMongoDbSettings>();

        services.AddIdentityMongoDbProvider<MilvaMongoTemplateUser, MilvaMongoTemplateRole, ObjectId>(identityOptions,
                                                                        mongo =>
                                                                        {
                                                                            mongo.ConnectionString = $"{mongoSettings.ConnectionString}/{mongoSettings.DatabaseName}";
                                                                            mongo.UsersCollection = CollectionNames.MilvaMongoTemplateUsers;
                                                                            mongo.RolesCollection = CollectionNames.MilvaMongoTemplateRoles;
                                                                        })
                .AddUserValidator<MilvaUserValidation<MilvaMongoTemplateUser, ObjectId, IStringLocalizer<SharedResource>>>()
                .AddErrorDescriber<MilvaIdentityDescriber<IStringLocalizer<SharedResource>>>()
                .AddUserManager<MilvaMongoTemplateUserManager>()
                .AddRoles<MilvaMongoTemplateRole>()
                .AddDefaultTokenProviders()
                /*.AddPersonalDataProtection<LookupProtector, KeyRing>()*/;
    }

    /// <summary>
    /// Configures JWT Token Authentication.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="jSONFile"></param>
    public static void AddJwtBearer(this IServiceCollection services, IJsonOperations jSONFile)
    {
        var localizer = services.BuildServiceProvider().GetRequiredService<IStringLocalizer<SharedResource>>();

        var tokenManagement = jSONFile.GetCryptedContentAsync<TokenManagement>(Path.Combine(GlobalConstant.JsonFilesPath,
                                                                                            "tokenmanagement.json")).Result;

        services.AddSingleton<ITokenManagement>(tokenManagement);

        var tokenValidationParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(tokenManagement.Secret)),
            ValidateIssuer = false,
            ValidIssuer = string.Empty,
            ValidateAudience = false,
            ValidAudience = string.Empty,
            ValidateLifetime = true
        };

        services.AddSingleton(tokenValidationParams);

        services.AddAuthentication(opt =>
        {
            opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(opt =>
        {
            IStringLocalizer<SharedResource> GetLocalizerInstance(HttpContext httpContext)
            {
                return httpContext.RequestServices.GetRequiredService<IStringLocalizer<SharedResource>>();
            }

            Task ReturnResponse(HttpContext httpContext, string localizerKey, int statusCode)
            {
                if (!httpContext.Response.HasStarted)
                {
                    var localizer = GetLocalizerInstance(httpContext);

                    ExceptionResponse validationResponse = new()
                    {
                        Message = localizer[localizerKey],
                        Success = false,
                        StatusCode = statusCode
                    };

                    httpContext.Response.ContentType = "application/json";
                    httpContext.Response.StatusCode = MilvaStatusCodes.Status200OK;
                    return httpContext.Response.WriteAsync(JsonConvert.SerializeObject(validationResponse));
                }
                return Task.CompletedTask;
            }

            opt.Events = new JwtBearerEvents()
            {
                //Token içinde name kontrol etme
                OnTokenValidated = (context) =>
            {
                if (string.IsNullOrEmpty(context.Principal.Identity.Name) || context.SecurityToken is not JwtSecurityToken accessToken)
                {
                    var localizer = GetLocalizerInstance(context.HttpContext);

                    context.Fail(localizer["Unauthorized"]);
                    return ReturnResponse(context.HttpContext, "Unauthorized", MilvaStatusCodes.Status401Unauthorized);
                }

                return Task.CompletedTask;
            },
                OnForbidden = context =>
                {
                    return ReturnResponse(context.HttpContext, "Forbidden", MilvaStatusCodes.Status403Forbidden);
                },
                OnChallenge = context =>
                {
                    // Skip the default logic.
                    context.HandleResponse();

                    return ReturnResponse(context.HttpContext, "Unauthorized", MilvaStatusCodes.Status401Unauthorized);
                },
                OnAuthenticationFailed = context =>
                {
                    string localizerKey = "Unauthorized";

                    if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        localizerKey = "TokenExpired";

                    return ReturnResponse(context.HttpContext, localizerKey, MilvaStatusCodes.Status401Unauthorized);
                }
            };


            opt.RequireHttpsMetadata = false;
            opt.SaveToken = true;
            opt.TokenValidationParameters = tokenValidationParams;
        });
    }

    /// <summary>
    /// Configures DI.
    /// </summary>
    /// <param name="services"></param>
    public static void ConfigureDependencyInjection(this IServiceCollection services)
    {
        services.AddSingleton<SharedResource>();

        services.AddSingleton<IMilvaMailSender>(new MilvaMailSender(GlobalConstant.AppMail,
                                                                    new NetworkCredential(GlobalConstant.AppMail, string.Empty),
                                                                    587,
                                                                    "mail.yourdomain.com"));

        services.AddScoped((_) => new MilvaEncryptionProvider(GlobalConstant.MilvaMongoTemplateKey));

        services.AddScoped<IMilvaLogger, MilvaMongoTemplateLogger>();

        services.AddScoped<IApplicationBuilder, ApplicationBuilder>();

        services.AddTransient(typeof(Lazy<>), typeof(MilvaLazy<>));

        #region Repositories

        services.AddScoped(typeof(IBaseRepository<>), typeof(BaseRepository<>));

        #endregion

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
        var mongoSettings = jsonOperations.GetCryptedContentAsync<MongoDbSettings>(Path.Combine(GlobalConstant.JsonFilesPath,
                                                                                   $"connectionstring.{Startup.WebHostEnvironment.EnvironmentName}.json")).Result;

        services.AddSingleton<IMongoDbSettings>(mongoSettings);
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
