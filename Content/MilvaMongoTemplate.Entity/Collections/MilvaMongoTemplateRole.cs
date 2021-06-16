using AspNetCore.Identity.Mongo.Model;
using MilvaMongoTemplate.Entity.Utils;
using Milvasoft.Helpers.DataAccess.Abstract.Entity;
using Milvasoft.Helpers.DataAccess.MongoDB.Utils;
using MongoDB.Bson;
using System;

namespace MilvaMongoTemplate.Entity.Collections
{
    /// <summary>
    /// Roles of app.
    /// </summary>
    [BsonCollection(CollectionNames.MilvaMongoTemplateRoles)]
    public class MilvaMongoTemplateRole : MongoRole<ObjectId>, IAuditable<ObjectId>
    {
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
