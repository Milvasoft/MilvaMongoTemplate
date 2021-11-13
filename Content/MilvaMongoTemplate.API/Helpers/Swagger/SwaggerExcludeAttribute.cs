using System;

namespace MilvaMongoTemplate.API.Helpers.Swagger;

/// <summary>
/// Excludes property from swagger documentation.
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public class SwaggerExcludeAttribute : Attribute
{
}
