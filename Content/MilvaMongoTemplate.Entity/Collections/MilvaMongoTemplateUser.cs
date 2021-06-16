using AspNetCore.Identity.Mongo.Model;
using MilvaMongoTemplate.Entity.EmbeddedDocuments;
using MilvaMongoTemplate.Entity.Utils;
using Milvasoft.Helpers.DataAccess.Abstract.Entity;
using Milvasoft.Helpers.DataAccess.MongoDB.Utils;
using MongoDB.Bson;
using System;

namespace MilvaMongoTemplate.Entity.Collections
{
    /// <summary>
    /// App user.
    /// </summary>
    [BsonCollection(CollectionNames.MilvaMongoTemplateUsers)]
    public class MilvaMongoTemplateUser : MongoUser<ObjectId>, IAuditable<ObjectId>
    {
        /// <summary>
        /// Last modification date of entity.
        /// </summary>
        public DateTime? LastModificationDate { get; set; }

        /// <summary>
        /// Creation date of entity.
        /// </summary>
        //public DateTime CreationDate { get => Id.CreationTime; set { } } // TODO prodda aç.
        public DateTime CreationDate { get; set; }

        /// <summary>
        /// Name of app user.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Surname of app user.
        /// </summary>
        public string Surname { get; set; }

        /// <summary>
        /// Determines whether the account has been deleted.
        /// </summary>
        public bool IsDeleted { get; set; } = false;

        /// <summary>
        /// If this user is not mobile application user, this embedded document will be empty.
        /// </summary>
        public AppUser AppUser { get; set; }
    }
}
