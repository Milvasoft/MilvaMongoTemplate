using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using MilvaMongoTemplate.Entity.Collections;
using Milvasoft.Core;
using Milvasoft.Core.Exceptions;
using Milvasoft.Core.Extensions;
using Milvasoft.DataAccess.MongoDB.Utils;
using Milvasoft.DataAccess.MongoDB.Utils.Serializers;
using Milvasoft.DataAccess.MongoDB.Utils.Settings;
using Milvasoft.Encryption.Abstract;
using Milvasoft.Identity.Abstract;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace MilvaMongoTemplate.Data.Utils;

/// <summary>
/// Class that performs database reset process.
/// </summary>
public static class DataSeed
{
    /// <summary>
    /// Default admin user name.
    /// </summary>
    public const string AdminUserName = "sampleadmin";

    private static IMongoDatabase _mongoDatabase;
    private static IMilvaEncryptionProvider _milvaEncryptionProvider;

    /// <summary>
    /// Resets all data in the database.
    /// </summary>
    /// <returns></returns>
    public static async Task ResetDataAsync(this IApplicationBuilder app)
    {
        var mongoDbSettings = app.ApplicationServices.GetRequiredService<IMongoDbSettings>();
        var mongoClient = app.ApplicationServices.GetRequiredService<IMongoClient>();

        _milvaEncryptionProvider = app.ApplicationServices.GetRequiredService<IMilvaEncryptionProvider>();

        _mongoDatabase = mongoClient.GetDatabase(mongoDbSettings.DatabaseName);

        await InitializeRolesAsync().ConfigureAwait(false);
        await InitializeUsersAsync(app.ApplicationServices.GetRequiredService<IMilvaUserManager<MilvaMongoTemplateUser, ObjectId>>()).ConfigureAwait(false);

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
    private static async Task InitializeRolesAsync()
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
            };

        await InitializeDataAsync(roles);
    }

    /// <summary>
    /// Initializes <see cref="MilvaMongoTemplateUser"/> to database.
    /// </summary>
    /// <returns></returns>
    private static async Task InitializeUsersAsync(IMilvaUserManager<MilvaMongoTemplateUser, ObjectId> userManager)
    {
        var users = new List<MilvaMongoTemplateUser>
            {
                new MilvaMongoTemplateUser
                {
                     Id = 1.ToObjectId(),
                     NameSurname = (EncryptedString)"Admin",
                     UserName = AdminUserName,
                     CreationDate = DateTime.UtcNow,
                     Email = "admin@milvasoft.com",
                     PhoneNumber = "905060998500",
                     Roles = new()
                     {
                         "Administrator"
                     }
                }
            };

        var collection = GetMongoCollection<MilvaMongoTemplateUser>();
        await collection.DeleteManyAsync(Builders<MilvaMongoTemplateUser>.Filter.Empty).ConfigureAwait(false);

        foreach (var user in users)
        {
            var userPassword = $"{user.UserName}-!";

            user.NameSurname = user.NameSurname;
            user.PhoneNumber = user.PhoneNumber;

            userManager.ConfigureForCreate(user, userPassword);
        }

        await InitializeDataAsync(users);
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

    private static async Task CreateIndexesAsync<TEntity>(Func<IEnumerable<CreateIndexModel<TEntity>>> func, CancellationToken cancellationToken = default)
        => await _mongoDatabase.GetCollection<TEntity>(typeof(TEntity).GetCollectionName()).Indexes.CreateManyAsync(func(), cancellationToken).ConfigureAwait(false);

    private static async Task CreateIndexesAsync<TEntity>(Func<IEnumerable<CreateIndexModel<TEntity>>> func, CreateManyIndexesOptions options, CancellationToken cancellationToken = default)
        => await _mongoDatabase.GetCollection<TEntity>(typeof(TEntity).GetCollectionName()).Indexes.CreateManyAsync(func(), options, cancellationToken).ConfigureAwait(false);

    private static async Task CreateIndexAsync<TEntity>(Func<CreateIndexModel<TEntity>> func, CreateOneIndexOptions options = null, CancellationToken cancellationToken = default)
        => await _mongoDatabase.GetCollection<TEntity>(typeof(TEntity).GetCollectionName()).Indexes.CreateOneAsync(func(), options, cancellationToken).ConfigureAwait(false);

    #endregion
}
