using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers.Attributes.Validation;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs
{
    /// <summary>
    /// DTO to be used in creation processes.
    /// </summary>
    public class AppUserUpdateDTO : DocumentBaseDTO
    {
        /// <summary>
        /// Gives information about whether there is a first update process after registration.
        /// </summary>
        public bool FirsUpdate { get; set; }

        /// <summary>
        /// Name of to be created user by admin.
        /// </summary>
        [MValidateString(3, 25, MemberNameLocalizerKey = "LocalizedName")]
        public string NewName { get; set; }

        /// <summary>
        /// Surname of to be created user by admin.
        /// </summary>
        [MValidateString(3, 25, MemberNameLocalizerKey = "LocalizedSurname")]
        public string NewSurname { get; set; }

        /// <summary>
        /// Phone number which can be entered in initial update process after registeration process.
        /// </summary>
        [MValidateString(0, 16)]
        [MilvaRegex(typeof(SharedResource), IsRequired = false)]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// User's identity number. (e.g. TC number)
        /// </summary>
        public string IdentityNumber { get; set; }
    }
}
