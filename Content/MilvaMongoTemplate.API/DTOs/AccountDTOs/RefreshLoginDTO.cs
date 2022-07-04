using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// The model to be used when refresh login operation.
/// </summary>
public class RefreshLoginDTO
{
    /// <summary>
    /// Refresh token which user have.
    /// </summary>
    [MValidateString(500)]
    public string RefreshToken { get; set; }

    /// <summary>
    /// Old valid token which user have.
    /// </summary>
    [MValidateString(500)]
    public string OldToken { get; set; }

    /// <summary>
    /// The mobile phone mac address.
    /// </summary>
    [MValidateString(100)]
    public string MacAddress { get; set; }
}
