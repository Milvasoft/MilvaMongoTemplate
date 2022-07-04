using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using Milvasoft.Attributes.Validation;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// DTO to be used to check user existance.
/// </summary>
public record CheckUserExistanceDTO
{
    /// <summary>
    /// The username for check.
    /// </summary>
    [MValidateString(3, 40)]
    public string UserName { get; init; }

    /// <summary>
    /// Email for check.
    /// </summary>
    [MValidateString(0, 75, MemberNameLocalizerKey = "LocalizedEmail")]
    [MilvaRegex(typeof(SharedResource), IsRequired = false, MemberNameLocalizerKey = "Email", ExampleFormatLocalizerKey = "RegexExampleEmail")]
    public string Email { get; init; }
}
