using Milvasoft.Helpers.DataAccess.EfCore.Abstract.Entity;
using MongoDB.Bson;
using System;

namespace MilvaMongoTemplate.Entity.EmbeddedDocuments;

/// <summary>
/// App user embedded document for sample.
/// </summary>
public class AppUser : IAuditable<ObjectId>
{
    /// <summary>
    /// Last modification date of entity.
    /// </summary>
    public DateTime? LastModificationDate { get; set; }

    /// <summary>
    /// Creation date of entity.
    /// </summary>
    public DateTime CreationDate { get; set; }

    /// <summary>
    /// Unique key of entity.
    /// </summary>
    public ObjectId Id { get; set; }

    /// <summary>
    /// User's identity number. (e.g. TC number)
    /// </summary>
    public string IdentityNumber { get; set; }
}
