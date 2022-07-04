using MilvaMongoTemplate.Entity.Utils;
using Milvasoft.Core.EntityBase.Concrete;
using Milvasoft.DataAccess.MongoDB.Utils.Attributes;
using MongoDB.Bson;
using System;
using System.Linq.Expressions;

namespace MilvaMongoTemplate.Entity.Collections;

/// <summary>
/// Roles of app.
/// </summary>
[BsonCollection(CollectionNames.MilvaMongoTemplateRoles)]
public class MilvaMongoTemplateRole : FullAuditableEntityWithCustomUser<MilvaMongoTemplateUser, ObjectId, ObjectId>
{
    /// <summary>
    /// Name of role.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Normalized name of role.
    /// </summary>
    public string NormalizedName { get; set; }

    #region Projections

    /// <summary>
    /// Projection for methods.
    /// </summary>
    public static Expression<Func<MilvaMongoTemplateRole, MilvaMongoTemplateRole>> NameProjection
    {
        get => r => new MilvaMongoTemplateRole
        {
            Id = r.Id,
            Name = r.Name
        };
    }

    #endregion

}
