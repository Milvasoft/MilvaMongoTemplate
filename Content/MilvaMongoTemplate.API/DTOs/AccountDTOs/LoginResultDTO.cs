using Microsoft.AspNetCore.Identity;
using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using Milvasoft.Identity.Abstract;
using Milvasoft.Identity.Concrete;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// Login result information.
/// </summary>
public class LoginResultDTO : ILoginResultDTO<MilvaToken>
{
    /// <summary>
    /// If login not success.
    /// </summary>
    public List<IdentityError> ErrorMessages { get; set; }

    /// <summary>
    /// If login is success.
    /// </summary>
    [MValidateString(5000)]
    public MilvaToken Token { get; set; }
}
