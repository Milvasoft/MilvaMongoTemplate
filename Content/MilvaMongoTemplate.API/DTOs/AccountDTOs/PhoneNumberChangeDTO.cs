using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using Milvasoft.Attributes.Validation;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// DTO to be used to change phone number.
/// </summary>
public record PhoneNumberChangeDTO
{
    /// <summary>
    /// The user who wants to change phone number.
    /// </summary>
    [MValidateString(3, 20)]
    public string UserName { get; init; }

    /// <summary>
    /// New phone number.
    /// </summary>
    [MValidateString(0, 16, MemberNameLocalizerKey = "LocalizedPhoneNumber")]
    [MilvaRegex(typeof(SharedResource), IsRequired = false, MemberNameLocalizerKey = "PhoneNumber", ExampleFormatLocalizerKey = "RegexExamplePhoneNumber")]
    public string NewPhoneNumber { get; init; }

    /// <summary>
    /// Phone number verification code if phone number will change.
    /// </summary>
    public string VerificationCode { get; set; }
}
