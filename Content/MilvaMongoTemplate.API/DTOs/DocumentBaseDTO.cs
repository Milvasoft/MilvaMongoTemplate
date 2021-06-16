using MilvaMongoTemplate.API.Helpers;
using Milvasoft.Helpers.DataAccess.Abstract.Entity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using Newtonsoft.Json;
using System;

namespace MilvaMongoTemplate.API.DTOs
{
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
}
