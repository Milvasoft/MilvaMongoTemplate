using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers.Attributes.Validation;
using MongoDB.Bson;
using System.Collections.Generic;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs
{
    /// <summary>
    /// DTO to be used in creation processes.
    /// </summary>
    public class MilvaMongoTemplateUserCreateDTO : DocumentBaseDTO
    {
        /// <summary>
        /// UserName of to be created user by admin.
        /// </summary>
        [MValidateString(3, 20)]
        public string UserName { get; set; }

        /// <summary>
        /// Name of to be created user by admin.
        /// </summary>
        [MValidateString(3, 25)]
        public string Name { get; set; }

        /// <summary>
        /// Surname of to be created user by admin.
        /// </summary>
        [MValidateString(3, 25)]
        public string Surname { get; set; }

        /// <summary>
        /// Email of to be created user by admin.
        /// </summary>
        [MValidateString(7, 75)]
        [MilvaRegex(typeof(SharedResource), IsRequired = false)]
        public string Email { get; set; }

        /// <summary>
        /// PhoneNumber of to be created user by admin.
        /// </summary>
        [MValidateString(0, 16)]
        [MilvaRegex(typeof(SharedResource), IsRequired = false)]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Password of to be created user by admin.
        /// </summary>
        [MValidateString(5, 75)]
        public string Password { get; set; }

        /// <summary>
        /// Roles of to be created user by admin.
        /// </summary>
        public List<ObjectId> Roles { get; set; }

    }
}
