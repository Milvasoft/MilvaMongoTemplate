using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using MilvaMongoTemplate.API.DTOs.AccountDTOs;
using MilvaMongoTemplate.API.Services.Abstract;
using MilvaMongoTemplate.Data.Utils;

namespace MilvaMongoTemplate.API.Controllers;

/// <summary>
/// Provides competition's CRUD operations for admin and competition's operations for app users.
/// </summary>
[Route(GlobalConstant.FullRoute)]
[ApiController]
[ApiVersion("1.0")]
[ApiExplorerSettings(GroupName = "v1.0")]
//[Authorize(Roles = RoleNames.Developer)]
[ConfigureAwait(false)]
public class DeveloperOpsController : ControllerBase
{
    private readonly MilvaMongoTemplateUserManager _userManager;
    private readonly IAccountService _accountService;

    /// <summary>
    /// Initializes new instances of <see cref="DeveloperOpsController"/>.
    /// </summary>
    /// <param name="userManager"></param>
    /// <param name="accountService"></param>
    public DeveloperOpsController(MilvaMongoTemplateUserManager userManager,
                                  IAccountService accountService)
    {
        _userManager = userManager;
        _accountService = accountService;
    }

    /// <summary>
    /// Switch environment.
    /// </summary>
    /// <returns></returns>
    [HttpGet("Switch/AppEnv")]
    public IActionResult SwitchAppEnv()
    {
        var oldState = GlobalConstant.RealProduction;

        GlobalConstant.RealProduction = !GlobalConstant.RealProduction;

        return Ok($"{oldState} => {GlobalConstant.RealProduction}");
    }

    #region For Development

    /// <summary>
    /// Return any user token.
    /// </summary>
    /// <returns></returns>
    [HttpGet("AnyToken")]
    [AllowAnonymous]
    public async Task<IActionResult> GetAnyAdminToken()
    {
        var users = _userManager.Users;

        if (users.IsNullOrEmpty())
            throw new MilvaUserFriendlyException("No users found.");

        var user = users.First();

        var loginDTO = new LoginDTO
        {
            Password = $"{user.UserName}+1234",
            UserName = user.UserName
        };

        var result = await _accountService.LoginAsync(loginDTO);

        result.Token.AccessToken = $"Bearer {result.Token.AccessToken}";

        return Ok(result);
    }

    /// <summary>
    /// Reset database.
    /// </summary>
    /// <returns></returns>
    [HttpGet("Reset/Database")]
    public async Task<IActionResult> ResetEntities()
    {
        var applicationBuilder = HttpContext.RequestServices.GetRequiredService<IApplicationBuilder>();

        await applicationBuilder.ResetDataAsync();

        return Ok("Database successfully reseted.");
    }

    #endregion
}
