using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Milvasoft.Core.Utils.Models.Response;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace MilvaMongoTemplate.API.Helpers.Attributes.ActionFilters;

/// <summary>
/// Authorizes opsiyon api.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
[ConfigureAwait(false)]
public class MilvaAuthorizeAttribute : Attribute, IAsyncAuthorizationFilter
{
    private readonly List<List<string>> _listOfRoleLists;

    /// <summary>
    /// Initializes new instance of <see cref="MilvaAuthorizeAttribute"/>.
    /// </summary>
    /// <param name="roles"></param>
    public MilvaAuthorizeAttribute(params string[] roles)
    {
        _listOfRoleLists = new();

        var tempList = new List<string>();

        var count = roles.Count();

        for (int i = 0; i < count; i++)
        {
            if (count == i + 1)
            {
                tempList.Add(roles[i]);
                _listOfRoleLists.Add(tempList);
                break;
            }

            if (roles[i] != "&")
            {
                tempList.Add(roles[i]);
                continue;
            }
            else
            {
                _listOfRoleLists.Add(tempList);
                tempList = new List<string>();
            }
        }

    }

    /// <summary>
    /// Authorization according to valid tokens.
    /// </summary>
    /// <param name="context"></param>
    /// <returns></returns>
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        #region Get Required Application Services

        var localizer = context.HttpContext.RequestServices.GetService<IStringLocalizer<SharedResource>>();
        var userRepository = context.HttpContext.RequestServices.GetService<IBaseRepository<MilvaMongoTemplateUser>>();
        var tokenValidationParams = context.HttpContext.RequestServices.GetService<TokenValidationParameters>();
        var userName = context.HttpContext.User.Identity.Name;

        #endregion

        //If token not exists.
        var tokenExists = context.HttpContext.Request.Headers.TryGetValue(StringKey.Authorization, out StringValues token);

        if (!tokenExists)
        {
            await ReturnResponseAsync(nameof(ResourceKey.Unauthorized), MilvaStatusCodes.Status401Unauthorized, context);
            return;
        }

        //Remove Bearer text.
        token = token.ToString().Remove(0, 7);

        var principals = GetPrincipalAndValidateToken(token, tokenValidationParams);

        //If it is null this mean token is invalid.
        if (principals == null)
        {
            await ReturnResponseAsync(nameof(ResourceKey.Unauthorized), MilvaStatusCodes.Status401Unauthorized, context);
            return;
        }
        else
        {
            foreach (var list in _listOfRoleLists)
            {
                bool isHaveRole = false;

                foreach (var role in list)
                {
                    //If user's roles does not contains required roles.
                    if (principals.IsInRole(role))
                    {
                        isHaveRole = true;
                        break;
                    }
                }

                if (!isHaveRole)
                {
                    await ReturnResponseAsync(nameof(ResourceKey.Forbidden), MilvaStatusCodes.Status403Forbidden, context);
                    return;
                }
            }
        }

        var user = await userRepository.GetFirstOrDefaultAsync(x => x.UserName == userName, MilvaMongoTemplateUser.AuthorizationAttributeProjection);

        if (user == null || (user.AppUser != null && (user.ValidTokens.IsNullOrEmpty() || !user.ValidTokens.Any(i => i.TokenString == token))))
        {
            await ReturnResponseAsync(nameof(ResourceKey.LoggedOutPleaseRelogin), MilvaStatusCodes.Status401Unauthorized, context);
            return;
        }

        static Task ReturnResponseAsync(string localizerKey, int statusCode, AuthorizationFilterContext context)
        {
            var localizer = context.HttpContext.RequestServices.GetRequiredService<IStringLocalizer<SharedResource>>();

            ExceptionResponse validationResponse = new()
            {
                Message = localizer[localizerKey],
                Success = false,
                StatusCode = statusCode
            };

            context.Result = new OkObjectResult(validationResponse);

            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Returns Claims in token for token decode
    /// </summary>
    private static ClaimsPrincipal GetPrincipalAndValidateToken(string token, TokenValidationParameters tokenValidationParameters)
    {
        try
        {
            JwtSecurityTokenHandler tokenHandler = new();

            JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);

            if (jwtToken == null)
                return null;

            TokenValidationParameters parameters = tokenValidationParameters;

            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, parameters, out SecurityToken securityToken);

            return principal;
        }
        catch (Exception)
        {
            return null;
        }
    }
}

