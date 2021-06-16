using MilvaMongoTemplate.API.Helpers;
using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using MongoDB.Bson;
using Newtonsoft.Json;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs
{
    /// <summary>
    /// Roles of app.
    /// </summary>
    public class MilvaMongoTemplateRoleDTO
    {
        /// <summary>
        /// Id of role.
        /// </summary>
        [JsonConverter(typeof(ObjectIdJsonConverter))]
        public ObjectId Id { get; set; }

        /// <summary>
        /// Name of role.
        /// </summary>
        [MValidateString(2, 50)]
        public string Name { get; set; }
    }
}
