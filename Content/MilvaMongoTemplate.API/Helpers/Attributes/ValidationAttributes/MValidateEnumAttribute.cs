using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers.Attributes.Validation;
using System;

namespace MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;

/// <summary>
/// Determines minimum decimal value.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = false)]
public class MValidateEnumAttribute : ValidateEnumAttribute
{
    /// <summary>
    /// Constructor of atrribute.
    /// </summary>
    public MValidateEnumAttribute() : base(typeof(SharedResource)) { }

    /// <summary>
    /// Constructor of atrribute.
    /// </summary>
    /// <param name="enumType"></param>
    public MValidateEnumAttribute(Type enumType) : base(typeof(SharedResource), enumType) { }
}
