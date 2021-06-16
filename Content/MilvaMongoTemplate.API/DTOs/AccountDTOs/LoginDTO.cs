using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs
{
    /// <summary>
    /// Login and sign up processes are happens with this dto.
    /// </summary>
    public class LoginDTO
    {
        /// <summary>
        /// UserName of user.
        /// </summary>
        [MValidateString(3, 20)]
        public string UserName { get; set; }

        /// <summary>
        /// Password of user.
        /// </summary>
        [MValidateString(5, 75)]
        public string Password { get; set; }

    }
}
