using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MilvaMongoTemplate.Entity.Collections;
using Milvasoft.Helpers.DataAccess.MongoDB.Utils;
using Milvasoft.Helpers.Encryption.Concrete;
using Milvasoft.Helpers.Exceptions;
using Milvasoft.Helpers.Extensions;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace MilvaMongoTemplate.Data.Utils;

/// <summary>
/// Class that performs database reset process.
/// </summary>
public static class DataSeed
{
    private static IMongoDatabase _mongoDatabase;
    private static MilvaEncryptionProvider _milvaEncryptionProvider;

    /// <summary>
    /// Resets all data in the database.
    /// </summary>
    /// <returns></returns>
    public static async Task ResetDataAsync(this IApplicationBuilder app)
    {
        var mongoDbSettings = app.ApplicationServices.GetRequiredService<IMongoDbSettings>();

        _milvaEncryptionProvider = app.ApplicationServices.GetRequiredService<MilvaEncryptionProvider>();

        _mongoDatabase = new MongoClient(mongoDbSettings.ConnectionString).GetDatabase(mongoDbSettings.DatabaseName);

        NoSqlRelationHelper.DbName = mongoDbSettings.DatabaseName;

        await InitializeRolesAsync(app.ApplicationServices.GetRequiredService<RoleManager<MilvaMongoTemplateRole>>()).ConfigureAwait(false);
        await InitializeUsersAsync(app.ApplicationServices.GetRequiredService<MilvaMongoTemplateUserManager>()).ConfigureAwait(false);

        //await ConfigureIndexes().ConfigureAwait(false);
    }

    /// <summary>
    /// Returns <see cref="IMongoCollection{TDocument}"/>.
    /// </summary>
    /// <typeparam name="TEntity"></typeparam>
    /// <returns></returns>
    private static IMongoCollection<TEntity> GetMongoCollection<TEntity>()
    {
        return _mongoDatabase.GetCollection<TEntity>(typeof(TEntity).GetCollectionName());
    }

    /// <summary>
    /// Initializes <paramref name="entities"/> to database.
    /// </summary>
    /// <typeparam name="TEntity"></typeparam>
    /// <param name="entities"></param>
    /// <returns></returns>
    private static async Task InitializeDataAsync<TEntity>(List<TEntity> entities) where TEntity : class, new()
    {
        //_mongoDatabase.CreateCollectionAsync(typeof(TEntity).GetCollectionName(), new CreateCollectionOptions { Collation = new Collation("tr") }).Wait();

        var collection = GetMongoCollection<TEntity>();

        await collection.Indexes.DropAllAsync().ConfigureAwait(false);

        await collection.DeleteManyAsync(Builders<TEntity>.Filter.Empty).ConfigureAwait(false);

        if (!entities.IsNullOrEmpty())
            await collection.InsertManyAsync(entities).ConfigureAwait(false);
    }

    /// <summary>
    /// Initializes <see cref="MilvaMongoTemplateRole"/> to database.
    /// </summary>
    /// <returns></returns>
    private static async Task InitializeRolesAsync(RoleManager<MilvaMongoTemplateRole> roleManager)
    {
        var roles = new List<MilvaMongoTemplateRole>
            {
                new MilvaMongoTemplateRole
                {
                    Id = 1.ToObjectId(),
                    Name = "Admin"
                },
                new MilvaMongoTemplateRole
                {
                    Id = 2.ToObjectId(),
                    Name = "Editor"
                },
                new MilvaMongoTemplateRole
                {
                    Id = 3.ToObjectId(),
                    Name = "AppUser"
                },
                new MilvaMongoTemplateRole
                {
                    Id = 4.ToObjectId(),
                    Name = "Developer"
                },
                new MilvaMongoTemplateRole
                {
                    Id = 5.ToObjectId(),
                    Name = "PaymentOfficer"
                }
            };

        foreach (var role in roles)
            await roleManager.CreateAsync(role).ConfigureAwait(false);
    }

    /// <summary>
    /// Initializes <see cref="MilvaMongoTemplateUser"/> to database.
    /// </summary>
    /// <returns></returns>
    private static async Task InitializeUsersAsync(MilvaMongoTemplateUserManager userManager)
    {
        var users = new List<MilvaMongoTemplateUser>
            {
                new MilvaMongoTemplateUser
                {
                    Id = 13.ToObjectId(),
                    Name = "Admin",
                    Surname = "Admin",
                    UserName = "admin",
                    CreationDate = DateTime.Now,
                    Email = "admin@milvasoft.com",
                    PhoneNumber = "0 506 000 00 00",
                    Roles = new()
                    {
                        1.ToObjectId().ToString()
                    }
                }
            };

        var collection = GetMongoCollection<MilvaMongoTemplateUser>();
        await collection.DeleteManyAsync(Builders<MilvaMongoTemplateUser>.Filter.Empty).ConfigureAwait(false);

        foreach (var user in users)
        {
            var userPassword = $"{user.Name.ToUpper().First()}{user.Surname.ToLower().First()}+1234";

            user.Name = await _milvaEncryptionProvider.EncryptAsync(user.Name).ConfigureAwait(false);
            user.Surname = await _milvaEncryptionProvider.EncryptAsync(user.Surname).ConfigureAwait(false);
            user.PhoneNumber = await _milvaEncryptionProvider.EncryptAsync(user.PhoneNumber).ConfigureAwait(false);

            if (user.AppUser != null)
                if (!string.IsNullOrEmpty(user.AppUser.IdentityNumber))
                    user.AppUser.IdentityNumber = await _milvaEncryptionProvider.EncryptAsync(user.AppUser.IdentityNumber).ConfigureAwait(false);

            await userManager.CreateAsync(user, userPassword).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Configured indexes.
    /// </summary>
    /// <returns></returns>
    private static async Task ConfigureIndexes()
    {
        throw new MilvaUserFriendlyException(MilvaException.FeatureNotImplemented);
    }

    #region Helper Methods

    /// <summary>
    /// Converts <paramref name="value"/>'s type to <see cref="ObjectId"/>
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    private static ObjectId ToObjectId(this int value)
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

    private static async Task CreateIndexesAsync<TEntity>(Func<IEnumerable<CreateIndexModel<TEntity>>> func, CancellationToken cancellationToken = default)
        => await _mongoDatabase.GetCollection<TEntity>(typeof(TEntity).GetCollectionName()).Indexes.CreateManyAsync(func(), cancellationToken).ConfigureAwait(false);

    private static async Task CreateIndexesAsync<TEntity>(Func<IEnumerable<CreateIndexModel<TEntity>>> func, CreateManyIndexesOptions options, CancellationToken cancellationToken = default)
        => await _mongoDatabase.GetCollection<TEntity>(typeof(TEntity).GetCollectionName()).Indexes.CreateManyAsync(func(), options, cancellationToken).ConfigureAwait(false);

    private static async Task CreateIndexAsync<TEntity>(Func<CreateIndexModel<TEntity>> func, CreateOneIndexOptions options = null, CancellationToken cancellationToken = default)
        => await _mongoDatabase.GetCollection<TEntity>(typeof(TEntity).GetCollectionName()).Indexes.CreateOneAsync(func(), options, cancellationToken).ConfigureAwait(false);

    #endregion
}
