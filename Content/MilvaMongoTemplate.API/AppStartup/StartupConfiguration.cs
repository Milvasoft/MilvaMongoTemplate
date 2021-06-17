﻿using Fody;
using MilvaMongoTemplate.API.Helpers;
using Milvasoft.Helpers.Encryption.Concrete;
using Milvasoft.Helpers.FileOperations.Abstract;
using Milvasoft.Helpers.Models;
using System.Globalization;
using System.IO;
using System.Threading.Tasks;

namespace MilvaMongoTemplate.API.AppStartup
{
    /// <summary>
    /// Class in which initial configurations are specified.
    /// </summary>
    [ConfigureAwait(false)]
    public static class StartupConfiguration
    {

        /// <summary>
        /// Checks media library folders. If folders not exists creates that folders.
        /// </summary>
        public static void CheckPublicFiles()
        {
            if (!Directory.Exists(GlobalConstants.MediaLibraryPath))
            {
                Directory.CreateDirectory(GlobalConstants.MediaLibraryPath);
                Directory.CreateDirectory(GlobalConstants.ImageLibraryPath);
                Directory.CreateDirectory(GlobalConstants.ARModelLibraryPath);
                Directory.CreateDirectory(GlobalConstants.VideoLibraryPath);
                Directory.CreateDirectory(GlobalConstants.DocumentLibraryPath);
            }
            if (!Directory.Exists(GlobalConstants.ImageLibraryPath))
            {
                Directory.CreateDirectory(GlobalConstants.ImageLibraryPath);
            }
            if (!Directory.Exists(GlobalConstants.ARModelLibraryPath))
            {
                Directory.CreateDirectory(GlobalConstants.ARModelLibraryPath);
            }
            if (!Directory.Exists(GlobalConstants.VideoLibraryPath))
            {
                Directory.CreateDirectory(GlobalConstants.VideoLibraryPath);
            }
            if (!Directory.Exists(GlobalConstants.DocumentLibraryPath))
            {
                Directory.CreateDirectory(GlobalConstants.DocumentLibraryPath);
            }
        }

        /// <summary>
        /// For development.
        /// </summary>
        /// <returns></returns>
        public static async Task EncryptFile()
        {
            var provider = new MilvaEncryptionProvider(GlobalConstants.MilvaMongoTemplateKey);

            await provider.EncryptFileAsync(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "stringblacklist.json"));
            await provider.EncryptFileAsync(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "allowedfileextensions.json"));
            await provider.EncryptFileAsync(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "tokenmanagement.json"));
            await provider.EncryptFileAsync(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "connectionstring.Development.json"));
            await provider.EncryptFileAsync(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "connectionstring.Production.json"));
        }

        /// <summary>
        /// For development.
        /// </summary>
        /// <returns></returns>
        public static async Task DecryptFile()
        {
            var provider = new MilvaEncryptionProvider(GlobalConstants.MilvaMongoTemplateKey);

            await provider.DecryptFileAsync(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "stringblacklist.json"));
            await provider.DecryptFileAsync(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "allowedfileextensions.json"));
            await provider.DecryptFileAsync(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "tokenmanagement.json"));
            await provider.DecryptFileAsync(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "connectionstring.Development.json"));
            await provider.DecryptFileAsync(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "connectionstring.Production.json"));
        }

        /// <summary>
        /// Fills <c> GlobalConstants.StringBlackList </c> list from stringblacklist.json file.
        /// </summary>
        /// <param name="jsonOperations"></param>
        /// <returns></returns>
        public static async Task FillStringBlacklistAsync(IJsonOperations jsonOperations)
        {
            GlobalConstants.StringBlacklist = await jsonOperations.GetRequiredContentFromCryptedJsonFileAsync<InvalidString>(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "stringblacklist.json"),
                                                                                                                            GlobalConstants.MilvaMongoTemplateKey,
                                                                                                                                new CultureInfo("tr-TR"));
        }

        /// <summary>
        /// Fills <c> GlobalConstants.AllowedFileExtensions </c> list from allowedfileextensions.json file.
        /// </summary>
        /// <param name="jsonOperations"></param>
        /// <returns></returns>
        public static async Task FillAllowedFileExtensionsAsync(IJsonOperations jsonOperations)
        {
            GlobalConstants.AllowedFileExtensions = await jsonOperations.GetRequiredContentFromCryptedJsonFileAsync<AllowedFileExtensions>(Path.Combine(GlobalConstants.RootPath, "StaticFiles", "JSON", "allowedfileextensions.json"),
                                                                                                                                            GlobalConstants.MilvaMongoTemplateKey,
                                                                                                                                                new CultureInfo("tr-TR"));
        }
    }
}