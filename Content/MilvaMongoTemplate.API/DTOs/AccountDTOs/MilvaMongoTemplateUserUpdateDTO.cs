using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers.Attributes.Validation;
using MongoDB.Bson;
using System.Collections.Generic;

namespace MilvaMongoTemplate.API.DTOs.AccountDTOs;

/// <summary>
/// DTO to be used in creation processes.
/// </summary>
public class MilvaMongoTemplateUserUpdateDTO : DocumentBaseDTO
{
    /// <summary>
    /// Name of to be created user by admin.
    /// </summary>
    [MValidateString(3, 25, MemberNameLocalizerKey = "LocalizedName")]
    public string NewName { get; set; }

    /// <summary>
    /// Surname of to be created user by admin.
    /// </summary>
    [MValidateString(3, 25, MemberNameLocalizerKey = "LocalizedSurname")]
    public string NewSurname { get; set; }

    /// <summary>
    /// Email of to be created user by admin.
    /// </summary>
    [MValidateString(0, 75, MemberNameLocalizerKey = "LocalizedEmail")]
    [MilvaRegex(typeof(SharedResource), IsRequired = false, MemberNameLocalizerKey = "Email", ExampleFormatLocalizerKey = "RegexExampleEmail")]
    public string NewEmail { get; set; }

    /// <summary>
    /// PhoneNumber of to be created user by admin.
    /// </summary>
    [MValidateString(0, 16, MemberNameLocalizerKey = "LocalizedPhoneNumber")]
    [MilvaRegex(typeof(SharedResource), IsRequired = false, MemberNameLocalizerKey = "PhoneNumber", ExampleFormatLocalizerKey = "RegexExamplePhoneNumber")]
    public string NewPhoneNumber { get; set; }

    /// <summary>
    /// Password of to be created user by admin.
    /// </summary>
    [MValidateString(0, 75, MemberNameLocalizerKey = "LocalizedPassword")]
    public string NewPassword { get; set; }

    /// <summary>
    /// Roles of to be created user by admin.
    /// </summary>
    public List<ObjectId> NewRoles { get; set; }

}
