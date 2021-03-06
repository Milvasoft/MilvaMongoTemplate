using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Milvasoft.Core.Utils.Models.Response;
using System.Globalization;
using System.IO;

namespace MilvaMongoTemplate.API.Helpers.Extensions;

/// <summary>
/// Helper extensions methods for Ops!yon Project.
/// </summary>
[ConfigureAwait(false)]
public static partial class HelperExtensions
{
    /// <summary>
    /// Addds is deleted filter to <paramref name="filterDefinition"/>.
    /// </summary>
    /// <param name="filterDefinition"></param>
    /// <returns></returns>
    public static FilterDefinition<MilvaMongoTemplateUser> AddIsDeletedFilter(this FilterDefinition<MilvaMongoTemplateUser> filterDefinition)
    {
        var isDeletedFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.IsDeleted, false);

        return Builders<MilvaMongoTemplateUser>.Filter.And(isDeletedFilter, filterDefinition);
    }

    /// <summary>
    /// Creates id and IsDeleted filter.
    /// </summary>
    /// <param name="id"></param>
    /// <returns></returns>
    public static FilterDefinition<MilvaMongoTemplateUser> CreateIdAndIsDeletedFilter(ObjectId id)
        => Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.Id, id).AddIsDeletedFilter();

    /// <summary>
    /// UserName id and IsDeleted filter.
    /// </summary>
    /// <param name="userName"></param>
    /// <returns></returns>
    public static FilterDefinition<MilvaMongoTemplateUser> CreateUserNameAndIsDeletedFilter(string userName)
        => Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, userName).AddIsDeletedFilter();

    /// <summary>
    /// Returns specific string localizer.
    /// </summary>
    /// <param name="cultureInfo"></param>
    /// <returns></returns>
    public static IStringLocalizer<SharedResource> GetSpecificStringLocalizer(this CultureInfo cultureInfo)
    {
        CultureInfo.CurrentCulture = cultureInfo;

        CultureInfo.CurrentUICulture = cultureInfo;

        var options = Options.Create(new LocalizationOptions { ResourcesPath = "Resources" });

        var factory = new ResourceManagerStringLocalizerFactory(options, new LoggerFactory());

        return new StringLocalizer<SharedResource>(factory);
    }

    /// <summary>
    /// Gets identity result as object response.
    /// </summary>
    /// <param name="asyncTask"></param>
    /// <param name="successMessage"></param>
    /// <param name="errorMessage"></param>
    /// <returns></returns>
    public static async Task<IActionResult> GetActivityResponseAsync(this Task<IdentityResult> asyncTask, string successMessage, string errorMessage)
    {
        ObjectResponse<IdentityResult> response = new()
        {
            Result = await asyncTask
        };

        if (!response.Result.Succeeded)
        {
            response.Message = errorMessage;
            response.StatusCode = MilvaStatusCodes.Status600Exception;
            response.Success = false;
        }
        else
        {
            response.Message = successMessage;
            response.StatusCode = MilvaStatusCodes.Status200OK;
            response.Success = true;
        }
        return new OkObjectResult(response);
    }

    /// <summary>
    /// Converts <paramref name="value"/>'s type to <see cref="ObjectId"/>
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static ObjectId ToObjectId(this int value)
    {
        var totalObjectIdLenth = ObjectId.GenerateNewId().ToString().Length;

        var valueConverted = value.ToString();

        if (totalObjectIdLenth <= valueConverted.Length) return new ObjectId("");

        string objectId = "";

        for (int i = 0; i < totalObjectIdLenth - valueConverted.Length; i++)
        {
            objectId += "0";
        }

        return new ObjectId(objectId + valueConverted);
    }

    /// <summary>
    /// Creates phone numver verification cache key.
    /// </summary>
    /// <param name="phoneNumber"></param>
    /// <returns></returns>
    public static string CreatePhoneNumberCacheKey(string phoneNumber) => $"mpvc_{phoneNumber}";

    /// <summary>
    /// Writes app start information to console.
    /// </summary>
    /// <param name="textWriter"></param>
    /// <param name="message"></param>
    public static void WriteAppInfo(this TextWriter textWriter, string message)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        textWriter.Write("\n\n info: ");
        Console.ForegroundColor = ConsoleColor.Gray;
        textWriter.Write($"{message}");
    }

    /// <summary>
    /// Writes app start information to console.
    /// </summary>
    /// <param name="textWriter"></param>
    /// <param name="message"></param>
    /// <returns></returns>
    public static async Task WriteAppInfoAsync(this TextWriter textWriter, string message)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        await textWriter.WriteAsync("\n\n info: ");
        Console.ForegroundColor = ConsoleColor.Gray;
        await textWriter.WriteAsync($"{message}");
    }

    /// <summary>
    /// Reads body from http request.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    public static async Task<string> ReadBodyFromRequestAsync(this HttpRequest request)
    {
        string json = null;

        if (request.HasJsonContentType())
        {
            if (request.Body.CanRead)
            {
                Stream requestStream = request.Body;

                requestStream.Seek(0, SeekOrigin.Begin);

                using var reader = new StreamReader(requestStream);

                json = await reader.ReadToEndAsync();

                request.Body.Position = 0;
            }
        }

        return json;
    }
}
