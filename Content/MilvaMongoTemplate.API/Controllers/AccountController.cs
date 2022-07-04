using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using MilvaMongoTemplate.API.DTOs.AccountDTOs;
using MilvaMongoTemplate.API.Helpers.Attributes.ActionFilters;
using MilvaMongoTemplate.API.Services.Abstract;
using MilvaMongoTemplate.Entity.Utils;
using Milvasoft.Identity.Concrete;

namespace MilvaMongoTemplate.API.Controllers;

/// <summary>
/// Provides account operations like login logout.
/// </summary>
[Route(GlobalConstant.FullRoute)]
[ApiController]
[ApiVersion("1.0")]
[ApiExplorerSettings(GroupName = "v1.0")]
[ConfigureAwait(false)]
public class AccountController : ControllerBase
{
    #region Fields

    private readonly IAccountService _accountService;
    private readonly IStringLocalizer<SharedResource> _sharedLocalizer;
    private readonly string _defaultSucccessMessage;

    #endregion

    /// <summary>
    /// Initializes new instances of <see cref="AccountController"/>.
    /// </summary>
    /// <param name="accountService"></param>
    /// <param name="sharedLocalizer"></param>
    public AccountController(IAccountService accountService, IStringLocalizer<SharedResource> sharedLocalizer)
    {
        _accountService = accountService;
        _sharedLocalizer = sharedLocalizer;
        _defaultSucccessMessage = _sharedLocalizer[nameof(ResourceKey.SuccessfullyOperationMessage)];
    }


    /// <summary>
    /// Provides sign in operation.
    /// </summary>
    /// 
    /// <remarks> 
    /// 
    /// <para> Both users(admin and mobile app user) should use this endpoint. </para>
    /// 
    /// </remarks>
    /// 
    /// <param name="loginDTO"></param>
    /// <returns></returns>
    [HttpPost("Login")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginResultDTO), MilvaStatusCodes.Status200OK)]
    public async Task<IActionResult> LoginAsync([FromBody] LoginDTO loginDTO)
    {
        var loginResult = await _accountService.LoginAsync(loginDTO);

        return loginResult.GetObjectResponse(_sharedLocalizer[nameof(ResourceKey.SuccessfullyLoginMessage)]);
    }

    /// <summary>
    /// Refresh token login for all users.
    /// </summary>
    /// <param name="refreshLoginDTO"></param>
    /// <returns></returns>
    [HttpPost("Login/{*refreshLogin}")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(MilvaToken), MilvaStatusCodes.Status200OK)]
    public async Task<IActionResult> RefreshTokenLogin(RefreshLoginDTO refreshLoginDTO)
    {
        var loginResult = await _accountService.RefreshTokenLogin(refreshLoginDTO);

        return loginResult.GetObjectResponse(_sharedLocalizer[nameof(ResourceKey.SuccessfullyLogoutMessage)]);
    }

    /// <summary>
    /// Provides user sign out operation.
    /// </summary>
    /// 
    /// <remarks> 
    /// 
    /// <para> Both users(admin and mobile app user) should use this endpoint. </para>
    /// 
    /// </remarks>
    /// <returns></returns>
    [HttpPut("Logout")]
    [MilvaAuthorize(RoleName.Administrator, RoleName.AppUser, RoleName.Developer)]
    public async Task<IActionResult> LogoutAsync()
        => await _accountService.LogoutAsync().GetObjectResponseAsync<object>(_sharedLocalizer[nameof(ResourceKey.SuccessfullyLogoutMessage)]);

    /// <summary>
    /// Returns logged-in user's account information.
    /// </summary>
    /// 
    /// <remarks> 
    /// 
    /// <para> Both users(admin and mobile app user) should use this endpoint. </para>
    /// 
    /// </remarks>
    /// 
    /// <returns></returns>
    [HttpGet("LoggedIn/User/Info")]
    [MilvaAuthorize(RoleName.Administrator, RoleName.AppUser, RoleName.Developer)]
    [ProducesResponseType(typeof(MilvaMongoTemplateUserDTO), MilvaStatusCodes.Status200OK)]
    public async Task<IActionResult> GetLoggedInInUserInformationAsync()
    {
        var user = await _accountService.GetLoggedInInUserInformationAsync();

        return user.GetObjectResponseByEntity(HttpContext, StringKey.AccountInfo);
    }

    #region AppUser

    /// <summary>
    /// Checks username and email existance.
    /// </summary>
    /// <param name="checkUserExistanceDTO"></param>
    /// <returns></returns>
    [HttpPatch("Check")]
    [AllowAnonymous]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> UserExistsAsync([FromBody] CheckUserExistanceDTO checkUserExistanceDTO)
        => await _accountService.UserExistsAsync(checkUserExistanceDTO)
                                .GetObjectResponseAsync<object>(_sharedLocalizer[nameof(ResourceKey.SuccessfullyOperationMessage)]);

    /// <summary>
    /// Provides the registration process of mobile application users.
    /// </summary>
    /// <param name="registerDTO"></param>
    /// <returns></returns>
    [HttpPost("Register")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginResultDTO), MilvaStatusCodes.Status200OK)]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> RegisterAsync([FromBody] RegisterDTO registerDTO)
    {
        var loginResult = await _accountService.RegisterAsync(registerDTO);

        return loginResult.GetObjectResponse(_sharedLocalizer[nameof(ResourceKey.SuccessfullyLoginMessage)]);
    }

    /// <summary>
    /// Deletes logged-in user's account.
    /// </summary>
    /// <returns></returns>
    [HttpDelete]
    [MilvaAuthorize(RoleName.AppUser)]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> DeleteAccountAsync()
        => await _accountService.DeleteAccountAsync().GetObjectResponseByEntityAsync<object>(HttpContext);

    #endregion

    #region Account Activities / Note : Editors can be use this endpoints too.

    /// <summary>
    /// Sends email verification mail to logged-in user's email address.
    /// </summary>
    /// 
    /// <remarks>
    /// 
    /// <para>Redirect link in the mail : <b> https://sampleappurl.com/verify?userName=sampleusername{AND}token=sampletoken </b> </para>
    /// 
    /// <para> <b>Note :</b> As "{AND}" is a special character, it is not suitable for a summary syntax. That's why it was written that way.</para>
    /// 
    /// </remarks>
    /// 
    /// <returns></returns>
    [HttpGet("Activity/Send/Mail/EmailVerification")]
    [MilvaAuthorize(RoleName.AppUser)]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> SendEmailVerificationMailAsync()
        => await _accountService.SendEmailVerificationMailAsync()
                                .GetObjectResponseByEntityAsync<object>(HttpContext, nameof(ResourceKey.EmailVerificationMailSent), false);

    /// <summary>
    /// Sends email change mail to logged-in user's email address.
    /// </summary>
    /// 
    /// <remarks>
    /// 
    /// <para>Redirect link in the mail : <b> https://sampleappurl.com/change/email?userName=sampleusername{AND}token=sampletoken </b> </para>
    /// 
    /// <para> <b>Note :</b> As "{AND}" is a special character, it is not suitable for a summary syntax. That's why it was written that way.</para>
    /// 
    /// </remarks>
    /// 
    /// <param name="newEmail"></param>
    /// <returns></returns>
    [HttpGet("Activity/Send/Mail/EmailChange/{newEmail}")]
    [MilvaAuthorize(RoleName.AppUser)]
    [MValidateStringParameter(2, 75)]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> SendChangeEmailMailAsync(string newEmail)
        => await _accountService.SendChangeEmailMailAsync(newEmail)
                                .GetObjectResponseByEntityAsync<object>(HttpContext, nameof(ResourceKey.EmailChangeMailSent), false);

    /// <summary>
    /// Sends password reset mail to logged-in user's email address.
    /// </summary>
    /// 
    /// <remarks>
    /// 
    /// <para>Redirect link in the mail : <b> https://sampleappurl.com/reset/password?userName=sampleusername{AND}token=sampletoken </b> </para>
    /// 
    /// <para> <b>Note :</b> As "{AND}" is a special character, it is not suitable for a summary syntax. That's why it was written that way.</para>
    /// 
    /// </remarks>
    /// <returns></returns>
    [HttpGet("Activity/Send/Mail/PasswordReset")]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> SendResetPasswordMailAsync()
        => await _accountService.SendResetPasswordMailAsync()
                                .GetObjectResponseByEntityAsync<object>(HttpContext, nameof(ResourceKey.PasswordResetMailSent), false);

    /// <summary>
    /// Sends password reset mail to email address(<paramref name="email"/>).
    /// </summary>
    /// 
    /// <remarks>
    /// 
    /// <para>Redirect link in the mail : <b> https://sampleappurl.com/reset/password?userName=sampleusername{AND}token=sampletoken </b> </para>
    /// 
    /// <para> <b>Note :</b> As "{AND}" is a special character, it is not suitable for a summary syntax. That's why it was written that way.</para>
    /// 
    /// </remarks>
    /// 
    /// <param name="email"></param>
    /// <returns></returns>
    [HttpGet("Activity/Send/Mail/ForgotPassword/{email}")]
    [MValidateStringParameter(3, 75)]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> SendForgotPasswordMailAsync(string email)
        => await _accountService.SendForgotPasswordMailAsync(email)
                                .GetObjectResponseByEntityAsync<object>(HttpContext, nameof(ResourceKey.PasswordResetMailSent), false);

    /// <summary>
    /// Sends verification code to phone number.
    /// </summary>
    /// <remarks>
    /// 
    /// <para><b> IMPORTANT INFORMATION : The message sending service has not yet been integrated. 
    ///                                   So this method will not send message to the user's gsm number.
    ///                                   Instead of returns verification code for testing. </b></para>
    /// 
    /// </remarks>
    /// 
    /// <returns></returns>
    [HttpGet("Activity/Send/Message/PhoneNumberVerification/{phoneNumber}")]
    [AllowAnonymous]
    [MValidateStringParameter(2, 30)]
    [ProducesResponseType(typeof(string), MilvaStatusCodes.Status200OK)]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> SendPhoneNumberVerificationMessageAsync(string phoneNumber)
    {
        var verificationMessage = await _accountService.SendPhoneNumberVerificationMessageAsync(phoneNumber);

        return verificationMessage.GetObjectResponse(nameof(ResourceKey.PhoneNumberVerificationMessageSent));
    }

    /// <summary>
    /// Verifies logged-in user's phone number.
    /// </summary>
    /// 
    /// <remarks>
    /// 
    /// The user must be logged-in because verification will be done from within the application.  
    /// 
    /// </remarks>
    /// 
    /// <param name="verificationCode"></param>
    /// <returns></returns>
    [HttpGet("Activity/Verify/PhoneNumber/{verificationCode}")]
    [MilvaAuthorize(RoleName.AppUser)]
    [MValidateStringParameter(2, 6)]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> VerifyPhoneNumberAsync(string verificationCode)
        => await _accountService.VerifyPhoneNumberAsync(verificationCode).GetObjectResponseByEntityAsync<object>(HttpContext);

    /// <summary>
    /// Verifies <paramref name="emailVerificationDTO"/>.UserName's email.
    /// </summary>
    /// <remarks>
    /// 
    /// The reason the user does not need to be logged in to request this endpoint is that the verification will take place on a web page outside of the application.
    /// 
    /// </remarks>
    /// 
    /// <param name="emailVerificationDTO"></param>
    /// <returns></returns>
    [HttpPut("Activity/Verify/Email")]
    [AllowAnonymous]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> VerifyEmailAsync([FromBody] EmailVerificationDTO emailVerificationDTO)
        => await _accountService.VerifyEmailAsync(emailVerificationDTO).GetObjectResponseByEntityAsync<object>(HttpContext);

    /// <summary>
    /// Changes <paramref name="emailChangeDTO"/>.UserName's email.
    /// </summary>
    /// <remarks>
    /// 
    /// The reason the user does not need to be logged in to request this endpoint is that the change process will take place on a web page outside of the application.
    /// 
    /// </remarks>
    /// 
    /// <param name="emailChangeDTO"></param>
    /// <returns></returns>
    [HttpPut("Activity/Change/Email")]
    [AllowAnonymous]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> ChangeEmailAsync([FromBody] EmailChangeDTO emailChangeDTO)
        => await _accountService.ChangeEmailAsync(emailChangeDTO).GetObjectResponseByEntityAsync<object>(HttpContext);

    /// <summary>
    /// Changes <paramref name="phoneNumberChangeDTO"/>.UserName's phone number.
    /// </summary>
    /// <remarks>
    /// 
    /// The reason the user does not need to be logged in to request this endpoint is that the change process will take place on a web page outside of the application.
    /// 
    /// </remarks>
    /// 
    /// <param name="phoneNumberChangeDTO"></param>
    /// <returns></returns>
    [HttpPut("Activity/Change/PhoneNumber")]
    [AllowAnonymous]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> ChangePhoneNumberAsync([FromBody] PhoneNumberChangeDTO phoneNumberChangeDTO)
        => await _accountService.ChangePhoneNumberAsync(phoneNumberChangeDTO).GetObjectResponseByEntityAsync<object>(HttpContext);

    /// <summary>
    /// Changes <paramref name="passwordChangeDTO"/>.UserName's password.
    /// </summary>
    /// <remarks>
    /// 
    /// The user must be logged-in because the change process will be done from within the application.
    /// 
    /// </remarks>
    /// 
    /// <param name="passwordChangeDTO"></param>
    /// <returns></returns>
    [HttpPut("Activity/Change/Password")]
    [MilvaAuthorize(RoleName.AppUser)]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> ChangePasswordAsync([FromBody] PasswordChangeDTO passwordChangeDTO)
        => await _accountService.ChangePasswordAsync(passwordChangeDTO).GetObjectResponseByEntityAsync<object>(HttpContext);

    /// <summary>
    /// Resets <paramref name="passwordResetDTO"/>.UserName's password.
    /// </summary>
    /// <remarks>
    /// 
    /// The reason the user does not need to be logged in to request this endpoint is that the reset process will take place on a web page outside of the application.
    /// 
    /// </remarks>
    /// 
    /// <param name="passwordResetDTO"></param>
    /// <returns></returns>
    [HttpPut("Activity/Reset/Password")]
    [AllowAnonymous]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public async Task<IActionResult> ResetPasswordAsync([FromBody] PasswordResetDTO passwordResetDTO)
        => await _accountService.ResetPasswordAsync(passwordResetDTO).GetObjectResponseByEntityAsync<object>(HttpContext);

    #endregion

    #region Admin

    /// <summary>
    /// Returns all administration users for admin user. You can transport data to modal from here.
    /// </summary>
    /// <param name="paginationParams"></param>
    /// <returns> Can be both Editors or Admins. </returns>
    [HttpPatch("Users")]
    [MilvaAuthorize(RoleName.Administrator)]
    [ProducesResponseType(typeof(PaginationDTO<MilvaMongoTemplateUserDTO>), MilvaStatusCodes.Status200OK)]
    public async Task<IActionResult> GetAllUsersAsync([FromBody] PaginationParams paginationParams)
    {
        var users = await _accountService.GetAllUsersAsync(paginationParams);

        return users.GetPaginationResponseByEntities(HttpContext, CollectionNames.MilvaMongoTemplateUsers, false);
    }

    /// <summary>
    /// Returns one administration user according to <paramref name="userId"/> for admin user.
    /// </summary>
    /// <param name="userId"></param>
    /// <returns> Can be both Editor or Admin. </returns>
    [HttpGet("Users/User/{userId}")]
    [MilvaAuthorize(RoleName.Administrator)]
    [ProducesResponseType(typeof(MilvaMongoTemplateUserDTO), MilvaStatusCodes.Status200OK)]
    public async Task<IActionResult> GetUserByIdAsync(ObjectId userId)
    {
        var user = await _accountService.GetUserByIdAsync(userId);

        return user.GetObjectResponseByEntity(HttpContext, CollectionNames.MilvaMongoTemplateUsers);
    }

    /// <summary>
    /// Creates one administration user according to <paramref name="userDTO"/>.
    /// </summary>
    /// <param name="userDTO"></param>
    /// <returns> Can be both Editors or Admins. </returns>
    [HttpPost("Users/User")]
    [MilvaAuthorize(RoleName.Administrator)]
    [ProducesResponseType(typeof(ObjectId), MilvaStatusCodes.Status200OK)]
    public async Task<IActionResult> CreateUserAsync([FromBody] MilvaMongoTemplateUserCreateDTO userDTO)
        => await _accountService.CreateUserAsync(userDTO).GetObjectResponseByEntityAsync(HttpContext);

    /// <summary>
    /// Updates one administration user according to <paramref name="userDTO"/>.
    /// </summary>
    /// <param name="userDTO"></param>
    /// <returns> Created user id. </returns>
    [HttpPut("Users/User")]
    [MilvaAuthorize(RoleName.Administrator)]
    public async Task<IActionResult> UpdateUserAsync([FromBody] MilvaMongoTemplateUserUpdateDTO userDTO)
        => await _accountService.UpdateUserAsync(userDTO).GetObjectResponseByEntityAsync<object>(HttpContext);

    /// <summary>
    /// Deletes one administration user according to <paramref name="userId"/>.
    /// </summary>
    /// <param name="userId"></param>
    /// <returns> Created user id. </returns>
    [HttpDelete("Users/User/{userId}")]
    [MilvaAuthorize(RoleName.Administrator)]
    public async Task<IActionResult> DeleteUserAsync(ObjectId userId)
        => await _accountService.DeleteUserAsync(userId).GetObjectResponseByEntityAsync<object>(HttpContext);

    /// <summary>
    /// Returns all app roles for combobox.
    /// </summary>
    /// <returns></returns>
    [HttpGet("Roles")]
    [MilvaAuthorize(RoleName.Administrator)]
    [ProducesResponseType(typeof(List<MilvaMongoTemplateRoleDTO>), MilvaStatusCodes.Status200OK)]
    public async Task<IActionResult> GetRolesAsync()
    {
        var roles = await _accountService.GetRolesAsync();

        roles.RemoveAll(i => i.Name == RoleName.Developer || i.Name == RoleName.AppUser);

        return roles.GetObjectResponseByEntities(HttpContext, CollectionNames.MilvaMongoTemplateRoles, isFiltering: false);
    }

    #endregion
}
