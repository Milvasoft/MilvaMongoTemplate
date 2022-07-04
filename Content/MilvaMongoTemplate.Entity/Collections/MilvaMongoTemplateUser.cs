using MilvaMongoTemplate.Entity.EmbeddedDocuments;
using MilvaMongoTemplate.Entity.Utils;
using Milvasoft.Core.EntityBase.Abstract;
using Milvasoft.DataAccess.MongoDB.Utils.Attributes;
using Milvasoft.DataAccess.MongoDB.Utils.Serializers;
using Milvasoft.Identity.Concrete.Entity;
using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;

namespace MilvaMongoTemplate.Entity.Collections;

/// <summary>
/// App user.
/// </summary>
[BsonCollection(CollectionNames.MilvaMongoTemplateUsers)]
public class MilvaMongoTemplateUser : MilvaUser<ObjectId>, IAuditable<ObjectId>
{
    private static readonly bool _developmentEnv = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";
    private DateTime _creationDate;

    /// <summary>
    /// Deletion date of entity.
    /// </summary>
    public DateTime? DeletionDate { get; set; }

    /// <summary>
    /// Last modification date of entity.
    /// </summary>
    public DateTime? LastModificationDate { get; set; }

    /// <summary>
    /// Creation date of entity.
    /// </summary>
    public virtual DateTime CreationDate
    {
        get => _developmentEnv ? _creationDate : Id.CreationTime;
        set
        {
            if (_developmentEnv)
                _creationDate = value;
        }
    }

    /// <summary>
    /// Name of app user.
    /// </summary>
    public EncryptedString NameSurname { get; set; }

    /// <summary>
    /// Determines whether the account has been deleted.
    /// </summary>
    public bool IsDeleted { get; set; } = false;

    /// <summary>
    /// Refresh token of user.
    /// </summary>
    public string RefreshToken { get; set; }

    /// <summary>
    /// User's valid tokens.
    /// </summary>
    public List<Token> ValidTokens { get; set; }

    /// <summary>
    /// User's valid tokens.
    /// </summary>
    public List<string> Roles { get; set; }

    /// <summary>
    /// If this user is not mobile application user, this embedded document will be empty.
    /// </summary>
    public AppUser AppUser { get; set; }


    #region Projections

    /// <summary>
    /// Projection for AccountService.SendActivityMailAsync method.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateUser, MilvaMongoTemplateUser>> AuthorizationAttributeProjection
    {
        get => o => new MilvaMongoTemplateUser
        {
            Id = o.Id,
            UserName = o.UserName,
            ValidTokens = o.ValidTokens,
            Roles = o.Roles,
            IsDeleted = o.IsDeleted
        };
    }

    /// <summary>
    /// Projection for AdministrationService.GetUserByUserNameAsync method.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateUser, MilvaMongoTemplateUser>> GetUserByUserNameProjection
    {
        get => o => new MilvaMongoTemplateUser
        {
            Id = o.Id,
            UserName = o.UserName,
            NameSurname = o.NameSurname,
            Email = o.Email,
            PhoneNumber = o.PhoneNumber,
            Roles = o.Roles,
            AppUser = o.AppUser,
            IsDeleted = o.IsDeleted
        };
    }

    /// <summary>
    /// Projection for AccountService.GetLoggedInInUserInformationAsync method.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateUser, MilvaMongoTemplateUser>> GetLoggedInUserInformationProjection
    {
        get => o => new MilvaMongoTemplateUser
        {
            Id = o.Id,
            UserName = o.UserName,
            NameSurname = o.NameSurname,
            Email = o.Email,
            EmailConfirmed = o.EmailConfirmed,
            PhoneNumber = o.PhoneNumber,
            PhoneNumberConfirmed = o.PhoneNumberConfirmed,
            Roles = o.Roles,
            IsDeleted = o.IsDeleted
        };
    }

    /// <summary>
    /// Projection for AccountService.GetLoggedPanelUserInfoAsync method.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateUser, MilvaMongoTemplateUser>> GetLoggedInPanelUserInformationProjection
    {
        get => o => new MilvaMongoTemplateUser
        {
            Id = o.Id,
            UserName = o.UserName,
            NameSurname = o.NameSurname,
            Email = o.Email,
            Roles = o.Roles,
            IsDeleted = o.IsDeleted
        };
    }

    /// <summary>
    /// Projection for AccountService.UpdateAccountAsync method.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateUser, MilvaMongoTemplateUser>> UpdateAccountProjection
    {
        get => o => new MilvaMongoTemplateUser
        {
            Id = o.Id,
            NameSurname = o.NameSurname,
            UserName = o.UserName,
            LastModificationDate = o.LastModificationDate,
            IsDeleted = o.IsDeleted,
        };
    }

    /// <summary>
    /// Projection for AccountService.DeleteAccountAsync method.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateUser, MilvaMongoTemplateUser>> DeleteAccountProjection
    {
        get => o => new MilvaMongoTemplateUser
        {
            Id = o.Id,
            UserName = o.UserName,
            AppUser = o.AppUser,
            IsDeleted = o.IsDeleted,
        };
    }

    /// <summary>
    /// Projection for AccountService.SendChangeEmailMailAsync method.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateUser, MilvaMongoTemplateUser>> EmailProjection
    {
        get => o => new MilvaMongoTemplateUser
        {
            Id = o.Id,
            Email = o.Email,
            IsDeleted = o.IsDeleted,
        };
    }

    /// <summary>
    /// Projection for AccountService.SendForgotPasswordMailAsync method.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateUser, MilvaMongoTemplateUser>> EmailAndUserNameProjection
    {
        get => o => new MilvaMongoTemplateUser
        {
            Id = o.Id,
            UserName = o.UserName,
            Email = o.Email,
            IsDeleted = o.IsDeleted,
        };
    }

    /// <summary>
    /// Projection for AccountService.GetAllUsersAsync method.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateUser, MilvaMongoTemplateUser>> GetUserProjection
    {
        get => o => new MilvaMongoTemplateUser
        {
            Id = o.Id,
            UserName = o.UserName,
            NameSurname = o.NameSurname,
            Email = o.Email,
            PhoneNumber = o.PhoneNumber,
            Roles = o.Roles,
            CreationDate = o.CreationDate,
            LastModificationDate = o.LastModificationDate,
            IsDeleted = o.IsDeleted,
        };
    }

    /// <summary>
    /// Projection for AccountService.SendActivityMailAsync method.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateUser, MilvaMongoTemplateUser>> SendActivityMailProjection
    {
        get => o => new MilvaMongoTemplateUser
        {
            Id = o.Id,
            UserName = o.UserName,
            NormalizedUserName = o.NormalizedUserName,
            PhoneNumber = o.PhoneNumber,
            PhoneNumberConfirmed = o.PhoneNumberConfirmed,
            Email = o.Email,
            NormalizedEmail = o.NormalizedEmail,
            EmailConfirmed = o.EmailConfirmed,
            PasswordHash = o.PasswordHash,
            IsDeleted = o.IsDeleted
        };
    }

    #endregion
}
