using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers.Attributes.Validation;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// DTO to be used to change email.
/// </summary>
public record EmailChangeDTO
{
    /// <summary>
    /// The user who wants to change email.
    /// </summary>
    [MValidateString(3, 20)]
    public string UserName { get; init; }

    /// <summary>
    /// New email.
    /// </summary>
    [MValidateString(7, 75, MemberNameLocalizerKey = "LocalizedEmail")]
    [MilvaRegex(typeof(SharedResource), IsRequired = false, MemberNameLocalizerKey = "Email", ExampleFormatLocalizerKey = "RegexExampleEmail")]
    public string NewEmail { get; init; }

    /// <summary>
    /// Email change token.
    /// </summary>
    [MValidateString(20, 1000, MemberNameLocalizerKey = "InvalidVerificationToken")]
    public string TokenString { get; init; }
}
