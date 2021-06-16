using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs
{
    /// <summary>
    /// DTO to be used to verify email.
    /// </summary>
    public record EmailVerificationDTO
    {
        /// <summary>
        /// The user who wants to verify email.
        /// </summary>
        [MValidateString(3, 20)]
        public string UserName { get; init; }

        /// <summary>
        /// Verification token.
        /// </summary>
        [MValidateString(20, 1000, MemberNameLocalizerKey = "InvalidVerificationToken")]
        public string TokenString { get; init; }
    }
}
