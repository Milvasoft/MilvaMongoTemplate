using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// DTO to be used to reset password.
/// </summary>
public record PasswordResetDTO
{
    /// <summary>
    /// The user who wants to change email.
    /// </summary>
    [MValidateString(3, 20)]
    public string UserName { get; init; }

    /// <summary>
    /// New password.
    /// </summary>
    [MValidateString(5, 75, MemberNameLocalizerKey = "LocalizedPassword")]
    public string NewPassword { get; init; }

    /// <summary>
    /// Password reset token.
    /// </summary>
    [MValidateString(20, 1000, MemberNameLocalizerKey = "InvalidVerificationToken")]
    public string TokenString { get; init; }
}
