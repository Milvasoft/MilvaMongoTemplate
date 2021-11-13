using Microsoft.AspNetCore.Mvc.Filters;
using MilvaMongoTemplate.API.DTOs.AccountDTOs;
using Milvasoft.Helpers.Attributes.ActionFilter;
using System;

namespace MilvaMongoTemplate.API.Helpers.Attributes.ActionFilters;

/// <summary>
///  Provides the attribute validation exclude opportunity.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public class MValidationFilterAttribute : ValidationFilterAttribute
{
    /// <summary>
    /// Performs when action executing.
    /// </summary>
    /// <param name="context"></param>
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        base.DTOFolderAssemblyName = "MilvaMongoTemplate.API.DTOs";
        base.AssemblyTypeForNestedProps = typeof(LoginDTO);
        base.OnActionExecuting(context);
    }
}
