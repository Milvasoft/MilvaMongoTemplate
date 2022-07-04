using MilvaMongoTemplate.API.Helpers;
using Milvasoft.Core.EntityBase.Abstract;
using MongoDB.Bson.Serialization.Attributes;
using Newtonsoft.Json;

namespace MilvaMongoTemplate.API.DTOs;

/// <summary>
/// Base entity for entities.
/// </summary>
public class DocumentBaseDTO : IAuditable<ObjectId>
{
    /// <summary>
    /// Unique key of entity.
    /// </summary>
    [BsonId]
    [BsonRepresentation(BsonType.String)]
    [JsonConverter(typeof(ObjectIdJsonConverter))]
    public ObjectId Id { get; set; }

    /// <summary>
    /// Last modification date of entity.
    /// </summary>
    public DateTime? LastModificationDate { get; set; }

    /// <summary>
    /// Creation date of entity.
    /// </summary>
    public DateTime CreationDate { get => Id.CreationTime; set { } }
}
