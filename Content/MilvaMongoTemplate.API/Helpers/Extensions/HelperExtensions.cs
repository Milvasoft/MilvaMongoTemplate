using Fody;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MilvaMongoTemplate.Entity.Collections;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers.DataAccess.Abstract.Entity;
using Milvasoft.Helpers.Exceptions;
using Milvasoft.Helpers.Extensions;
using Milvasoft.Helpers.FileOperations.Concrete;
using Milvasoft.Helpers.FileOperations.Enums;
using Milvasoft.Helpers.Models.Response;
using Milvasoft.Helpers.Utils;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace MilvaMongoTemplate.API.Helpers.Extensions
{
    /// <summary>
    /// Helper extensions methods for Ops!yon Project.
    /// </summary>
    [ConfigureAwait(false)]
    public static class HelperExtensions
    {
        #region IFormFile Helpers

        /// <summary>
        /// Validates file. 
        /// </summary>
        /// <param name="file"></param>
        /// <param name="fileType"></param>
        public static void ValidateFile(this IFormFile file, FileType fileType)
        {
            int maxFileLength = 14000000;

            var allowedFileExtensions = GlobalConstants.AllowedFileExtensions.Find(i => i.FileType == fileType.ToString()).AllowedExtensions;

            var validationResult = file.ValidateFile(maxFileLength, allowedFileExtensions, fileType);

            switch (validationResult)
            {
                case FileValidationResult.Valid:
                    break;
                case FileValidationResult.FileSizeTooBig:
                    // Get length of file in bytes
                    long fileSizeInBytes = file.Length;
                    // Convert the bytes to Kilobytes (1 KB = 1024 Bytes)
                    double fileSizeInKB = fileSizeInBytes / 1024;
                    // Convert the KB to MegaBytes (1 MB = 1024 KBytes)
                    double fileSizeInMB = fileSizeInKB / 1024;
                    throw new MilvaUserFriendlyException("FileIsTooBigMessage", fileSizeInMB.ToString("0.#"));
                case FileValidationResult.InvalidFileExtension:
                    throw new MilvaUserFriendlyException("UnsupportedFileTypeMessage", string.Join(", ", allowedFileExtensions));
                case FileValidationResult.NullFile:
                    throw new MilvaUserFriendlyException("FileCannotBeEmpty"); ;
            }
        }

        /// <summary>
        /// Save uploaded IFormFile file to server. Target Path will be : ".../wwwroot/Media Library/Image Library/<paramref name="entity"></paramref>.Id".
        /// </summary>
        /// <typeparam name="TEntity"></typeparam>
        /// <typeparam name="TKey"></typeparam>
        /// <param name="file"> Uploaded file in entity. </param>
        /// <param name="entity"></param>
        /// <returns></returns>
        public static async Task<string> SaveVideoToServerAsync<TEntity, TKey>(this IFormFile file, TEntity entity)
        {
            string basePath = GlobalConstants.VideoLibraryPath;

            FormFileOperations.FilesFolderNameCreator imagesFolderNameCreator = CreateVideoFolderNameFromDTO;

            string propertyName = "Id";

            int maxFileLength = 140000000;

            var allowedFileExtensions = GlobalConstants.AllowedFileExtensions.Find(i => i.FileType == FileType.Video.ToString()).AllowedExtensions;

            var validationResult = file.ValidateFile(maxFileLength, allowedFileExtensions, FileType.Video);

            switch (validationResult)
            {
                case FileValidationResult.Valid:
                    break;
                case FileValidationResult.FileSizeTooBig:
                    // Get length of file in bytes
                    long fileSizeInBytes = file.Length;
                    // Convert the bytes to Kilobytes (1 KB = 1024 Bytes)
                    double fileSizeInKB = fileSizeInBytes / 1024;
                    // Convert the KB to MegaBytes (1 MB = 1024 KBytes)
                    double fileSizeInMB = fileSizeInKB / 1024;
                    throw new MilvaUserFriendlyException("FileIsTooBigMessage", fileSizeInMB.ToString("0.#"));
                case FileValidationResult.InvalidFileExtension:
                    throw new MilvaUserFriendlyException("UnsupportedFileTypeMessage", string.Join(", ", allowedFileExtensions));
                case FileValidationResult.NullFile:
                    return "";
            }

            var path = await file.SaveFileToPathAsync(entity, basePath, imagesFolderNameCreator, propertyName);

            await file.OpenReadStream().DisposeAsync();

            return path;
        }

        /// <summary>
        /// Returns the path of the uploaded file.
        /// </summary>
        /// <param name="originalImagePath"> Uploaded file. </param>
        /// <param name="fileType"> Uploaded file type. (e.g image,video,sound) </param>
        public static string GetFileUrlFromPath(string originalImagePath, FileType fileType)
        {
            string libraryType = string.Empty;
            switch (fileType)
            {
                case FileType.Image:
                    libraryType = $"{GlobalConstants.RoutePrefix}/ImageLibrary";
                    break;
                case FileType.Video:
                    libraryType = $"{GlobalConstants.RoutePrefix}/VideoLibrary";
                    break;
                case FileType.ARModel:
                    libraryType = $"{GlobalConstants.RoutePrefix}/ARModelLibrary";
                    break;
                case FileType.Audio:
                    libraryType = $"{GlobalConstants.RoutePrefix}/AudioLibrary";
                    break;
                case FileType.Document:
                    libraryType = $"{GlobalConstants.RoutePrefix}/DocumentLibrary";
                    break;
                default:
                    break;
            }
            return FormFileOperations.GetFileUrlPathSectionFromFilePath(originalImagePath, libraryType);
        }

        /// <summary>
        /// Converts data URI formatted base64 string to IFormFile.
        /// </summary>
        /// <param name="milvaBase64"></param>
        /// <returns></returns>
        public static IFormFile ConvertToFormFile(string milvaBase64)
        {
            var splittedBase64String = milvaBase64.Split(";base64,");
            var base64String = splittedBase64String?[1];

            var contentType = splittedBase64String[0].Split(':')[1];

            var splittedContentType = contentType.Split('/');

            var fileType = splittedContentType?[0];

            var fileExtension = splittedContentType?[1];

            var array = Convert.FromBase64String(base64String);

            var memoryStream = new MemoryStream(array)
            {
                Position = 0
            };

            return new FormFile(memoryStream, 0, memoryStream.Length, fileType, $"File.{fileExtension}")
            {
                Headers = new HeaderDictionary(),
                ContentType = contentType
            };
        }

        private static string CreateImageFolderNameFromDTO(Type type)
        {
            return type.Name.Split("DTO")[0] + "Images";
        }

        private static string CreateVideoFolderNameFromDTO(Type type)
        {
            return type.Name + "Videos";
        }

        #endregion

        #region Language Helpers

        /// <summary>
        /// Stores language id and iso code.
        /// </summary>
        public static Dictionary<string, int> LanguageIdIsoPairs { get; set; } = new();

        private const string SystemLanguageIdString = "SystemLanguageId";

        /// <summary>
        /// Performs the necessary mapping for language dependent objects. For example, it is used to map the data in the Product class to the ProductDTO class.
        /// </summary>
        /// <param name="langs"></param>
        /// <param name="propertyName"></param>
        /// <returns></returns>
        public static string GetLang<TEntity>(this IEnumerable<TEntity> langs, Expression<Func<TEntity, string>> propertyName)
        {
            var requestedLangId = GetLanguageId(GlobalConstants.DefaultLanguageId);

            if (langs.IsNullOrEmpty()) return "";

            var propName = propertyName.GetPropertyName();

            TEntity requestedLang;

            if (requestedLangId != GlobalConstants.DefaultLanguageId) requestedLang = langs.FirstOrDefault(lang => (int)lang.GetType().GetProperty(SystemLanguageIdString).GetValue(lang) == requestedLangId)
                                                                                        ?? langs.FirstOrDefault(lang => (int)lang.GetType().GetProperty(SystemLanguageIdString).GetValue(lang) == GlobalConstants.DefaultLanguageId);

            else requestedLang = langs.FirstOrDefault(lang => (int)lang.GetType().GetProperty(SystemLanguageIdString).GetValue(lang) == GlobalConstants.DefaultLanguageId);

            requestedLang ??= langs.FirstOrDefault();

            return requestedLang.GetType().GetProperty(propName).GetValue(requestedLang, null)?.ToString();
        }

        /// <summary>
        /// Performs the necessary mapping for language dependent objects. For example, it is used to map the data in the Product class to the ProductDTO class.
        /// </summary>
        /// <param name="langs"></param>
        /// <returns></returns>
        public static IEnumerable<TDTO> GetLangs<TEntity, TDTO>(this IEnumerable<TEntity> langs) where TDTO : new()
        {
            if (langs.IsNullOrEmpty()) yield break;

            foreach (var lang in langs)
            {
                TDTO dto = new();
                foreach (var entityProp in lang.GetType().GetProperties())
                {
                    var dtoProp = dto.GetType().GetProperty(entityProp.Name);

                    var entityPropValue = entityProp.GetValue(lang, null);

                    if (entityProp.Name == SystemLanguageIdString) dtoProp.SetValue(dto, entityPropValue, null);

                    else if (entityProp.PropertyType == typeof(string)) dtoProp.SetValue(dto, entityPropValue, null);
                }
                yield return dto;
            }
        }

        /// <summary>
        /// Gets language id from CultureInfo.CurrentCulture.
        /// </summary>
        public static int GetLanguageId(int defaultLangId)
        {
            var culture = CultureInfo.CurrentCulture;
            if (LanguageIdIsoPairs.ContainsKey(culture.Name))
                return LanguageIdIsoPairs[culture.Name];
            else
                return defaultLangId;
        }

        #endregion

        #region Reflection Helpers

        /// <summary>
        /// Get langs property in runtime.
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="langPropName"></param>
        /// <param name="requestedPropName"></param>
        /// <returns></returns>
        public static dynamic GetLangPropValue(this object obj, string langPropName, string requestedPropName)
        {
            var langValues = obj.GetType().GetProperty(langPropName)?.GetValue(obj, null) ?? throw new MilvaUserFriendlyException(MilvaException.InvalidParameter);

            var enumerator = langValues.GetType().GetMethod("GetEnumerator").Invoke(langValues, null);
            enumerator.GetType().GetMethod("MoveNext").Invoke(enumerator, null);
            var entityType = enumerator.GetType().GetProperty("Current").GetValue(enumerator, null).GetType();

            MethodInfo langMethod = typeof(HelperExtensions).GetMethod("GetLang", BindingFlags.Static | BindingFlags.NonPublic).MakeGenericMethod(entityType);

            return langMethod.Invoke(langValues, new object[] { langValues, requestedPropName });
        }

        /// <summary>
        /// Performs the necessary mapping for language dependent objects. For example, it is used to map the data in the Product class to the ProductDTO class.
        /// </summary>
        /// <param name="langs"></param>
        /// <param name="propName"></param>
        /// <returns></returns>
        private static string GetLang<TEntity>(this HashSet<TEntity> langs, string propName)
        {
            var requestedLangId = GetLanguageId(GlobalConstants.DefaultLanguageId);

            if (langs.IsNullOrEmpty()) return "";

            TEntity requestedLang;

            if (requestedLangId != GlobalConstants.DefaultLanguageId) requestedLang = langs.FirstOrDefault(lang => (int)lang.GetType().GetProperty(SystemLanguageIdString).GetValue(lang) == requestedLangId)
                                                                                        ?? langs.FirstOrDefault(lang => (int)lang.GetType().GetProperty(SystemLanguageIdString).GetValue(lang) == GlobalConstants.DefaultLanguageId);

            else requestedLang = langs.FirstOrDefault(lang => (int)lang.GetType().GetProperty(SystemLanguageIdString).GetValue(lang) == GlobalConstants.DefaultLanguageId);

            requestedLang ??= langs.FirstOrDefault();

            return requestedLang.GetType().GetProperty(propName)?.GetValue(requestedLang, null)?.ToString();
        }

        /// <summary>
        /// Gets requested property value.
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="propertyName"> e.g : ProductLangs.Name </param>
        /// <returns></returns>
        public static object GetPropertyValue(this object obj, string propertyName)
        {
            var propNames = propertyName.Split('.').ToList();

            if (propNames.Count > 2) throw new MilvaUserFriendlyException(MilvaException.InvalidParameter);

            foreach (string propName in propNames)
            {
                if (typeof(IEnumerable).IsAssignableFrom(obj.GetType()))
                {
                    var count = (int)obj.GetType().GetProperty("Count").GetValue(obj, null);

                    var enumerator = obj.GetType().GetMethod("GetEnumerator").Invoke(obj, null);

                    List<object> listProp = new();

                    for (int i = 0; i < count; i++)
                    {
                        if (i == GlobalConstants.Zero) enumerator.GetType().GetMethod("MoveNext").Invoke(enumerator, null);

                        var currentValue = enumerator.GetType().GetProperty("Current").GetValue(enumerator, null);

                        var isLangPropExist = currentValue.GetType().GetProperties().Any(i => i.Name == "SystemLanguageId");
                        if (isLangPropExist)
                        {
                            var langId = (int)currentValue.GetType().GetProperty("SystemLanguageId").GetValue(currentValue, null);

                            if (langId == GetLanguageId(GlobalConstants.DefaultLanguageId))
                            {
                                obj = currentValue.GetType().GetProperty(propName).GetValue(currentValue, null);
                                break;
                            }
                        }
                        else
                        {
                            listProp.Add(currentValue.GetType().GetProperty(propName).GetValue(currentValue, null));
                        }

                        enumerator.GetType().GetMethod("MoveNext").Invoke(enumerator, null);
                    }
                    return listProp;

                }
                else obj = obj.GetType().GetProperty(propName).GetValue(obj, null);
            }

            return obj;
        }

        #endregion

        #region IEnumerable Helpers

        /// <summary>
        /// Checks guid list. If list is null or empty return default(<typeparamref name="TDTO"/>). Otherwise invoke <paramref name="returnFunc"/>.
        /// </summary>
        /// <typeparam name="TEntity"></typeparam>
        /// <typeparam name="TDTO"></typeparam>
        /// <param name="toBeCheckedList"></param>
        /// <param name="returnFunc"></param>
        /// <returns></returns>
        public static List<TDTO> CheckList<TEntity, TDTO>(this IEnumerable<TEntity> toBeCheckedList, Func<IEnumerable<TEntity>, IEnumerable<TDTO>> returnFunc)
         where TDTO : new()
         where TEntity : class, IBaseEntity<ObjectId>
         => toBeCheckedList.IsNullOrEmpty() ? new List<TDTO>() : returnFunc.Invoke(toBeCheckedList).ToList();

        /// <summary>
        /// Checks guid list. If list is null or empty return default(<typeparamref name="TDTO"/>). Otherwise invoke <paramref name="returnFunc"/>.
        /// </summary>
        /// <typeparam name="TEntity"></typeparam>
        /// <typeparam name="TDTO"></typeparam>
        /// <param name="toBeCheckedList"></param>
        /// <param name="returnFunc"></param>
        /// <returns></returns>
        public static async Task<List<TDTO>> CheckListAsync<TEntity, TDTO>(this IEnumerable<TEntity> toBeCheckedList, Func<IEnumerable<TEntity>, IEnumerable<Task<TDTO>>> returnFunc)
         where TDTO : new()
         where TEntity : class, IBaseEntity<ObjectId>
        {
            if (toBeCheckedList.IsNullOrEmpty())
                return new List<TDTO>();
            else
            {
                List<TDTO> tDTOs = new List<TDTO>();

                var result = returnFunc.Invoke(toBeCheckedList).ToList();

                foreach (var item in result)
                    tDTOs.Add(await item.ConfigureAwait(false));

                return tDTOs;
            }
        }

        /// <summary>
        /// Checks guid object. If is null return default(<typeparamref name="TDTO"/>). Otherwise invoke <paramref name="returnFunc"/>.
        /// </summary>
        /// <typeparam name="TEntity"></typeparam>
        /// <typeparam name="TDTO"></typeparam>
        /// <param name="toBeCheckedObject"></param>
        /// <param name="returnFunc"></param>
        /// <returns></returns>
        public static TDTO CheckObject<TEntity, TDTO>(this TEntity toBeCheckedObject, Func<TEntity, TDTO> returnFunc)
          where TDTO : new()
          where TEntity : class, IBaseEntity<ObjectId>
       => toBeCheckedObject == null ? default : returnFunc.Invoke(toBeCheckedObject);

        /// <summary>
        /// Checks guid object. If is null return default(<typeparamref name="TDTO"/>). Otherwise invoke <paramref name="returnFunc"/>.
        /// </summary>
        /// <typeparam name="TEntity"></typeparam>
        /// <typeparam name="TDTO"></typeparam>
        /// <param name="toBeCheckedObject"></param>
        /// <param name="returnFunc"></param>
        /// <returns></returns>
        public static async Task<TDTO> CheckObjectAsync<TEntity, TDTO>(this TEntity toBeCheckedObject, Func<TEntity, Task<TDTO>> returnFunc)
          where TDTO : new()
          where TEntity : class, IBaseEntity<ObjectId>
        {
            if (toBeCheckedObject != null)
            {
                var result = returnFunc.Invoke(toBeCheckedObject);

                return await result.ConfigureAwait(false);
            }
            else
                return default;
        }

        #endregion

        #region Exception Helpers

        /// <summary>
        /// Throwns <see cref="MilvaUserFriendlyException"/> if <paramref name="parameterObject"/> is null.
        /// </summary>
        /// <param name="parameterObject"></param>
        /// <param name="message"></param>
        public static void ThrowIfParameterIsNull(this object parameterObject, string message = null)
        {
            if (parameterObject == null)
            {
                if (string.IsNullOrEmpty(message))
                {
                    throw new MilvaUserFriendlyException(MilvaException.NullParameter);
                }
                else
                {
                    throw new MilvaUserFriendlyException(message);
                }
            }
        }

        /// <summary>
        /// Throwns <see cref="MilvaUserFriendlyException"/> if <paramref name="list"/> is null or empty.
        /// </summary>
        /// <param name="list"></param>
        /// <param name="message"></param>
        public static void ThrowIfListIsNullOrEmpty(this List<object> list, string message = null)
        {
            if (list.IsNullOrEmpty())
            {
                if (string.IsNullOrEmpty(message))
                {
                    throw new MilvaUserFriendlyException(MilvaException.CannotFindEntity);
                }
                else
                {
                    throw new MilvaUserFriendlyException(message);
                }
            }
        }

        /// <summary>
        /// Throwns <see cref="MilvaUserFriendlyException"/> if <paramref name="list"/> is null or empty.
        /// </summary>
        /// <param name="list"></param>
        /// <param name="message"></param>
        public static void ThrowIfParameterIsNullOrEmpty<T>(this List<T> list, string message = null) where T : IEquatable<T>
        {
            if (list.IsNullOrEmpty())
            {
                if (string.IsNullOrEmpty(message))
                {
                    throw new MilvaUserFriendlyException(MilvaException.NullParameter);
                }
                else
                {
                    throw new MilvaUserFriendlyException(message);
                }
            }
        }

        /// <summary>
        /// Throwns <see cref="MilvaUserFriendlyException"/> if <paramref name="list"/> is null or empty.
        /// </summary>
        /// <param name="list"></param>
        /// <param name="message"></param>
        public static void ThrowIfListIsNullOrEmpty(this IEnumerable<object> list, string message = null)
        {
            if (list.IsNullOrEmpty())
            {
                if (string.IsNullOrEmpty(message))
                {
                    throw new MilvaUserFriendlyException(MilvaException.CannotFindEntity);
                }
                else
                {
                    throw new MilvaUserFriendlyException(message);
                }
            }
        }

        /// <summary>
        /// Throwns <see cref="MilvaUserFriendlyException"/> if <paramref name="list"/> is not null or empty.
        /// </summary>
        /// <param name="list"></param>
        /// <param name="message"></param>
        public static void ThrowIfListIsNotNullOrEmpty(this IEnumerable<object> list, string message = null)
        {
            if (!list.IsNullOrEmpty())
            {
                if (string.IsNullOrEmpty(message))
                {
                    throw new MilvaUserFriendlyException(MilvaException.NullParameter);
                }
                else
                {
                    throw new MilvaUserFriendlyException(message);
                }
            }
        }

        /// <summary>
        /// Throwns <see cref="MilvaUserFriendlyException"/> if <paramref name="entity"/> is null.
        /// </summary>
        /// <param name="entity"></param>
        /// <param name="message"></param>
        public static void ThrowIfNullObject<TEntity>(this TEntity entity, string message = null) where TEntity : class, IBaseEntity<ObjectId>
        {

            if (entity == null)
            {
                if (string.IsNullOrEmpty(message))
                {
                    throw new MilvaUserFriendlyException(MilvaException.CannotFindEntity);
                }
                else
                {
                    throw new MilvaUserFriendlyException(message);
                }
            }
        }

        #endregion

        #region DateTime Helpers

        /// <summary>
        /// Compares <paramref name="date"/> for whether between <paramref name="startTime"/> and <paramref name="endTime"/>. 
        /// </summary>
        /// 
        /// <remarks>
        /// This is a time comparison not a date comparison.
        /// </remarks>
        /// 
        /// <param name="date"></param>
        /// <param name="startTime"></param>
        /// <param name="endTime"></param>
        /// <returns></returns>
        public static bool IsBetween(this DateTime date, TimeSpan startTime, TimeSpan endTime)
        {
            DateTime startDate = new(date.Year, date.Month, date.Day);
            DateTime endDate = startDate;

            //Check whether the endTime is lesser than startTime
            if (startTime >= endTime)
            {
                //Increase the date if endTime is timespan of the Nextday 
                endDate = endDate.AddDays(1);
            }

            //Assign the startTime and endTime to the Dates
            startDate = startDate.Date + startTime;
            endDate = endDate.Date + endTime;

            return (date >= startDate) && (date <= endDate);
        }

        /// <summary>
        /// Compares <paramref name="date"/> for whether between <paramref name="startDate"/> and <paramref name="endDate"/>. 
        /// </summary>
        /// <param name="date"></param>
        /// <param name="startDate"></param>
        /// <param name="endDate"></param>
        /// <returns></returns>
        public static bool IsBetween(this DateTime date, DateTime startDate, DateTime endDate) => (date >= startDate) && (date <= endDate);

        #endregion

        /// <summary>
        /// Addds is deleted filter to <paramref name="filterDefinition"/>.
        /// </summary>
        /// <param name="filterDefinition"></param>
        /// <returns></returns>
        public static FilterDefinition<MilvaMongoTemplateUser> AddIsDeletedFilter(this FilterDefinition<MilvaMongoTemplateUser> filterDefinition)
        {
            var isDeletedFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.IsDeleted, false);

            return Builders<MilvaMongoTemplateUser>.Filter.And(filterDefinition, isDeletedFilter);
        }

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
        public static async Task<IActionResult> GetActivityResponseAsync(this ConfiguredTaskAwaitable<IdentityResult> asyncTask, string successMessage, string errorMessage)
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
    }
}
