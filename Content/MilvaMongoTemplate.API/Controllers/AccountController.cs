using Fody;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using MilvaMongoTemplate.API.DTOs;
using MilvaMongoTemplate.API.DTOs.AccountDTOs;
using MilvaMongoTemplate.API.Helpers.Attributes.ActionFilters;
using MilvaMongoTemplate.API.Helpers.Constants;
using MilvaMongoTemplate.API.Helpers.Extensions;
using MilvaMongoTemplate.API.Services.Abstract;
using MilvaMongoTemplate.Entity.Utils;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers;
using Milvasoft.Helpers.Enums;
using MongoDB.Bson;
using System.Threading.Tasks;
using ResourceKey = MilvaMongoTemplate.Localization.Resources.SharedResource;

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
    /// Login method. This endpoint is accessible for anyone.
    /// </summary>
    /// <returns></returns>
    /// <param name="loginDTO"></param>
    /// <returns></returns>
    [HttpPost("Login")]
    [AllowAnonymous]
    [MValidationFilter]
    public async Task<IActionResult> LoginAsync([FromBody] LoginDTO loginDTO)
    {
        var loginResult = await _accountService.LoginAsync(loginDTO);

        return loginResult.GetObjectResponse(_sharedLocalizer[nameof(ResourceKey.SuccessfullyLoginMessage)]);
    }

    /// <summary>
    /// Refresh token login for all users.
    /// </summary>
    /// <param name="refreshLogin"></param>
    /// <returns></returns>
    [HttpPost("Login/{*refreshLogin}")]
    [AllowAnonymous]
    [MValidateStringParameter(10, 1000)]
    public async Task<IActionResult> RefreshTokenLogin(string refreshLogin)
    {
        var loginResult = await _accountService.RefreshTokenLogin(refreshLogin);

        return loginResult.GetObjectResponse(_sharedLocalizer[nameof(ResourceKey.SuccessfullyLoginMessage)]);
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
    [Authorize(Roles = RoleName.All)]
    public async Task<IActionResult> LogoutAsync()
        => await _accountService.LogoutAsync().GetObjectResponseAsync<object>(_sharedLocalizer[nameof(ResourceKey.SuccessfullyLoguotMessage)]);

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
    [Authorize(Roles = RoleName.All)]
    public async Task<IActionResult> GetLoggedInInUserInformationAsync()
    {
        var errorMessage = _sharedLocalizer.GetErrorMessage("User", CrudOperation.GetById);

        var user = await _accountService.GetLoggedInInUserInformationAsync();

        return user.GetObjectResponse(_defaultSucccessMessage, errorMessage);
    }

    #region AppUser

    /// <summary>
    /// Provides the registration process of mobile application users.
    /// </summary>
    /// <param name="registerDTO"></param>
    /// <returns></returns>
    [HttpPost("Register/{language}")]
    [AllowAnonymous]
    [MValidationFilter]
    public async Task<IActionResult> RegisterAsync([FromBody] RegisterDTO registerDTO)
    {
        var loginResult = await _accountService.RegisterAsync(registerDTO);

        return loginResult.GetObjectResponse(_sharedLocalizer[nameof(ResourceKey.SuccessfullyLoginMessage)]);
    }

    /// <summary>
    /// Updates logged-in user's personal information.
    /// </summary>
    /// <param name="userDTO"></param>
    /// <returns></returns>
    [HttpPut]
    [Authorize(Roles = RoleName.AppUser)]
    public async Task<IActionResult> UpdateMyAccountAsync(AppUserUpdateDTO userDTO)
    {
        var successMessage = _sharedLocalizer.GetSuccessMessage(MilvaMongoTemplateStringKey.Account, CrudOperation.Update);

        return await _accountService.UpdateAccountAsync(userDTO).GetObjectResponseAsync<object>(successMessage);
    }

    /// <summary>
    /// Deletes logged-in user's account.
    /// </summary>
    /// <returns></returns>
    [HttpDelete]
    [Authorize(Roles = RoleName.AppUser)]
    public async Task<IActionResult> DeleteAccountAsync()
    {
        var successMessage = _sharedLocalizer.GetSuccessMessage(MilvaMongoTemplateStringKey.Account, CrudOperation.Delete);

        return await _accountService.DeleteAccountAsync().GetObjectResponseAsync<object>(successMessage);
    }

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
    [Authorize(Roles = RoleName.AppUser)]
    public async Task<IActionResult> SendEmailVerificationMailAsync()
        => await _accountService.SendEmailVerificationMailAsync()
                                .GetObjectResponseByEntityAsync<object>(HttpContext, nameof(ResourceKey.EmailVerificationMailSent), false);

    /// <summary>
    /// Sends phone number change mail to logged-in user's email address.
    /// </summary>
    /// 
    /// <remarks>
    /// 
    /// <para>Redirect link in the mail : <b> https://sampleappurl.com/change/phoneNumber?userName=sampleusername{AND}token=sampletoken </b> </para>
    /// 
    /// <para> <b>Note :</b> As "{AND}" is a special character, it is not suitable for a summary syntax. That's why it was written that way.</para>
    /// 
    /// </remarks>
    /// 
    /// <param name="newPhoneNumber"></param>
    /// <returns></returns>
    [HttpGet("Activity/Send/Mail/PhoneNumberChange/{newPhoneNumber}")]
    [Authorize(Roles = RoleName.AppUser)]
    public async Task<IActionResult> SendChangePhoneNumberMailAsync(string newPhoneNumber)
        => await _accountService.SendChangePhoneNumberMailAsync(newPhoneNumber)
                                .GetObjectResponseByEntityAsync<object>(HttpContext, nameof(ResourceKey.PhoneNumberChangeMailSent), false);

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
    [Authorize(Roles = RoleName.AppUser)]
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
    [MValidateStringParameter(3, 30)]
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
    [MValidateStringParameter(3, 30)]
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
    [HttpGet("Activity/Send/Message/PhoneNumberVerification")]
    [Authorize(Roles = RoleName.AppUser)]
    public async Task<IActionResult> SendPhoneNumberVerificationMessageAsync()
        => await _accountService.SendPhoneNumberVerificationMessageAsync()
                                .GetObjectResponseByEntityAsync<object>(HttpContext, nameof(ResourceKey.PhoneNumberVerificationMessageSent), false);

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
    [Authorize(Roles = RoleName.AppUser)]
    public async Task<IActionResult> VerifyPhoneNumberAsync(string verificationCode)
        => await _accountService.VerifyPhoneNumberAsync(verificationCode).GetActivityResponseAsync(_sharedLocalizer[nameof(ResourceKey.PhoneNumberVerificationSuccessfull)],
                                                                                                   _sharedLocalizer[nameof(ResourceKey.AccountActivityErrorMessage)]);

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
    public async Task<IActionResult> VerifyEmailAsync([FromBody] EmailVerificationDTO emailVerificationDTO)
        => await _accountService.VerifyEmailAsync(emailVerificationDTO).GetActivityResponseAsync(_sharedLocalizer[nameof(ResourceKey.EmailVerificationSuccessfull)],
                                                                                                 _sharedLocalizer[nameof(ResourceKey.AccountActivityErrorMessage)]);

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
    public async Task<IActionResult> ChangeEmailAsync([FromBody] EmailChangeDTO emailChangeDTO)
        => await _accountService.ChangeEmailAsync(emailChangeDTO).GetActivityResponseAsync(_sharedLocalizer[nameof(ResourceKey.EmailChangeSuccessfull)],
                                                                                           _sharedLocalizer[nameof(ResourceKey.AccountActivityErrorMessage)]);

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
    public async Task<IActionResult> ChangePhoneNumberAsync([FromBody] PhoneNumberChangeDTO phoneNumberChangeDTO)
        => await _accountService.ChangePhoneNumberAsync(phoneNumberChangeDTO).GetActivityResponseAsync(_sharedLocalizer[nameof(ResourceKey.PhoneNumberChangeSuccessfull)],
                                                                                                       _sharedLocalizer[nameof(ResourceKey.AccountActivityErrorMessage)]);

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
    [Authorize(Roles = RoleName.AppUser)]
    public async Task<IActionResult> ChangePasswordAsync([FromBody] PasswordChangeDTO passwordChangeDTO)
        => await _accountService.ChangePasswordAsync(passwordChangeDTO).GetActivityResponseAsync(_sharedLocalizer[nameof(ResourceKey.PasswordChangeSuccessfull)],
                                                                                                 _sharedLocalizer[nameof(ResourceKey.AccountActivityErrorMessage)]);

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
    public async Task<IActionResult> ResetPasswordAsync([FromBody] PasswordResetDTO passwordResetDTO)
        => await _accountService.ResetPasswordAsync(passwordResetDTO).GetActivityResponseAsync(_sharedLocalizer[nameof(ResourceKey.PasswordResetSuccessfull)],
                                                                                               _sharedLocalizer[nameof(ResourceKey.AccountActivityErrorMessage)]);

    #endregion


    #region Admin

    /// <summary>
    /// Returns all administration users for admin user.
    /// </summary>
    /// <param name="paginationParams"></param>
    /// <returns> Can be both Editors or Admins. </returns>
    [HttpPatch("Users")]
    [Authorize(Roles = RoleName.Administrator)]
    public async Task<IActionResult> GetAllUsersAsync([FromBody] PaginationParams paginationParams)
    {
        var errorMessage = _sharedLocalizer.GetErrorMessage(MilvaMongoTemplateStringKey.User, CrudOperation.GetAll);

        var users = await _accountService.GetAllUsersAsync(paginationParams);

        return users.GetPaginationResponse(_defaultSucccessMessage, errorMessage);
    }

    /// <summary>
    /// Returns one administration user according to <paramref name="userId"/> for admin user.
    /// </summary>
    /// <param name="userId"></param>
    /// <returns> Can be both Editor or Admin. </returns>
    [HttpGet("Users/User/{userId}")]
    [Authorize(Roles = RoleName.Administrator)]
    public async Task<IActionResult> GetUserByIdAsync(ObjectId userId)
    {
        var errorMessage = _sharedLocalizer.GetErrorMessage(MilvaMongoTemplateStringKey.User, CrudOperation.GetById);

        var user = await _accountService.GetUserByIdAsync(userId);

        return user.GetObjectResponse(_defaultSucccessMessage, errorMessage);
    }

    /// <summary>
    /// Creates one administration user according to <paramref name="userDTO"/>.
    /// </summary>
    /// <param name="userDTO"></param>
    /// <returns> Can be both Editors or Admins. </returns>
    [HttpPost("Users/User")]
    [Authorize(Roles = RoleName.Administrator)]
    public async Task<IActionResult> CreateUserAsync([FromBody] MilvaMongoTemplateUserCreateDTO userDTO)
    {
        var successMessage = _sharedLocalizer.GetSuccessMessage(MilvaMongoTemplateStringKey.User, CrudOperation.Add);

        return await _accountService.CreateUserAsync(userDTO).GetObjectResponseAsync(successMessage);
    }

    /// <summary>
    /// Updates one administration user according to <paramref name="userDTO"/>.
    /// </summary>
    /// <param name="userDTO"></param>
    /// <returns> Created user id. </returns>
    [HttpPut("Users/User")]
    [Authorize(Roles = RoleName.Administrator)]
    public async Task<IActionResult> UpdateUserAsync([FromBody] MilvaMongoTemplateUserUpdateDTO userDTO)
    {
        var successMessage = _sharedLocalizer.GetSuccessMessage(MilvaMongoTemplateStringKey.User, CrudOperation.Update);

        return await _accountService.UpdateUserAsync(userDTO).GetObjectResponseAsync<object>(successMessage);
    }

    /// <summary>
    /// Deletes one administration user according to <paramref name="userId"/>.
    /// </summary>
    /// <param name="userId"></param>
    /// <returns> Created user id. </returns>
    [HttpDelete("Users/User/{userId}")]
    [Authorize(Roles = RoleName.Administrator)]
    public async Task<IActionResult> DeleteUserAsync(ObjectId userId)
    {
        var successMessage = _sharedLocalizer.GetSuccessMessage(MilvaMongoTemplateStringKey.User, CrudOperation.Delete);

        return await _accountService.DeleteUserAsync(userId).GetObjectResponseAsync<object>(successMessage);
    }

    /// <summary>
    /// Returns all obk app roles for combobox.
    /// </summary>
    /// <returns></returns>
    [HttpGet("Roles")]
    [Authorize(Roles = RoleName.Administrator)]
    public async Task<IActionResult> GetRolesAsync()
    {
        var errorMessage = _sharedLocalizer.GetErrorMessage(CollectionNames.MilvaMongoTemplateRoles, CrudOperation.GetAll);

        var roles = await _accountService.GetRolesAsync();

        roles.RemoveAll(i => i.Name == RoleName.Developer || i.Name == RoleName.AppUser);

        return roles.GetObjectResponse(_defaultSucccessMessage, errorMessage);
    }

    #endregion
}
