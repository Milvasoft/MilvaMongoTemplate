using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using Milvasoft.Attributes.Validation;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// DTO to be used in creation processes.
/// </summary>
public class MilvaMongoTemplateUserDTO : DocumentBaseDTO
{
    /// <summary>
    /// UserName of user.
    /// </summary>
    [MValidateString(3, 20)]
    public string UserName { get; set; }

    /// <summary>
    /// Name of user.
    /// </summary>
    [MValidateString(3, 25)]
    public string NameSurname { get; set; }

    /// <summary>
    /// User's identity number. (e.g. TC number)
    /// </summary>
    public string IdentityNumber { get; set; }

    /// <summary>
    /// Email of user.
    /// </summary>
    [MValidateString(7, 75)]
    [MilvaRegex(typeof(SharedResource), IsRequired = false)]
    public string Email { get; set; }

    /// <summary>
    /// Email confirmed information of user.
    /// </summary>
    public bool EmailConfirmed { get; set; }

    /// <summary>
    /// PhoneNumber of user.
    /// </summary>   
    [MValidateString(0, 16)]
    [MilvaRegex(typeof(SharedResource), IsRequired = false)]
    public string PhoneNumber { get; set; }

    /// <summary>
    /// Email confirmed information of user.
    /// </summary>
    public bool PhoneNumberConfirmed { get; set; }

    /// <summary>
    /// Roles of user.
    /// </summary>
    [MValidateString(0, 50)]
    public List<string> RoleNames { get; set; }
}
