using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// Sign up result.
/// </summary>
public class RegisterResultDTO
{
    /// <summary>
    /// Response message.
    /// </summary>
    [MValidateString(2000)]
    public string Message { get; set; }

    /// <summary>
    /// Local API token.
    /// </summary>
    [MValidateString(2000)]
    public string Token { get; set; }
}
