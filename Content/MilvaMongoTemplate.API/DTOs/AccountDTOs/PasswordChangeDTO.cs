using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// DTO to be used to reset password.
/// </summary>
public record PasswordChangeDTO
{
    /// <summary>
    /// New password.
    /// </summary>
    [MValidateString(5, 75)]
    public string OldPassword { get; init; }

    /// <summary>
    /// New password.
    /// </summary>
    [MValidateString(5, 75)]
    public string NewPassword { get; init; }
}
