using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers.Attributes.Validation;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// Login and sign up processes are happens with this dto.
/// </summary>
public class RegisterDTO : LoginDTO
{
    /// <summary>
    /// UserName of user.
    /// </summary>
    [MValidateString(7, 75)]
    [MilvaRegex(typeof(SharedResource), IsRequired = true)]
    public string Email { get; set; }
}
