using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using MilvaMongoTemplate.API.DTOs;
using MilvaMongoTemplate.API.DTOs.AccountDTOs;
using MilvaMongoTemplate.API.Helpers;
using MilvaMongoTemplate.API.Helpers.Attributes.ActionFilters;
using MilvaMongoTemplate.API.Helpers.Extensions;
using MilvaMongoTemplate.API.Services.Common.Abstract;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers;
using Milvasoft.Helpers.Enums;
using Milvasoft.Helpers.Extensions;
using Milvasoft.Helpers.Models.Response;
using Milvasoft.Helpers.Utils;
using MongoDB.Bson;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilvaMongoTemplate.API.Controllers
{
    [Route(GlobalConstants.FullRoute)]
    [ApiController]
    [ApiVersion("1.0")]
    [ApiExplorerSettings(GroupName = "v1.0")]
    public class AccountController : ControllerBase
    {
        #region Fields

        private readonly IAccountService _accountService;
        private readonly IStringLocalizer<SharedResource> _sharedLocalizer;
        private readonly string _defaultSucccessMessage;

        #endregion

        public AccountController(IAccountService accountService, IStringLocalizer<SharedResource> sharedLocalizer)
        {
            _accountService = accountService;
            _sharedLocalizer = sharedLocalizer;
            _defaultSucccessMessage = _sharedLocalizer["SuccessfullyOperationMessage"];
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
        [MValidationFilter]
        public async Task<IActionResult> LoginAsync([FromBody] LoginDTO loginDTO)
        {
            ObjectResponse<LoginResultDTO> response = new()
            {
                Result = await _accountService.LoginAsync(loginDTO).ConfigureAwait(false)
            };

            if (!response.Result.ErrorMessages.IsNullOrEmpty())
            {
                var stringBuilder = new StringBuilder();

                stringBuilder.AppendJoin(',', response.Result.ErrorMessages.Select(i => i.Description));

                response.Message = stringBuilder.ToString();

                //response.Message = string.Join("\r\n", response.Result.ErrorMessages.Select(m => m.Description));
                response.StatusCode = MilvaStatusCodes.Status400BadRequest; //status kod sonradan degistirlebilir.
                response.Success = false;
            } //Bu kontroller cogalabilir. orn her hata kodu icin kendine ozel status kod yazilabilir.
            else if (response.Result.Token == null)
            {
                response.Message = _sharedLocalizer["UnknownLoginProblemMessage"];
                response.StatusCode = MilvaStatusCodes.Status400BadRequest;
                response.Success = false;
            }
            else
            {
                response.Message = _sharedLocalizer["SuccessfullyLoginMessage"];
                response.StatusCode = MilvaStatusCodes.Status200OK;
                response.Success = true;
            }
            return Ok(response);
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
        [Authorize(Roles = RoleNames.All)]
        public async Task<IActionResult> LogoutAsync()
        {
            return await _accountService.LogoutAsync().ConfigureAwait(false).GetObjectResponseAsync<object>(_sharedLocalizer["SuccessfullyLoguotMessage"]);
        }

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
        [Authorize(Roles = RoleNames.All)]
        public async Task<IActionResult> GetLoggedInInUserInformationAsync()
        {
            var errorMessage = _sharedLocalizer.GetErrorMessage("User", CrudOperation.GetById);

            var user = await _accountService.GetLoggedInInUserInformationAsync().ConfigureAwait(false);

            return user.GetObjectResponse(_defaultSucccessMessage, errorMessage);
        }

        #region AppUser

        /// <summary>
        /// Provides the registration process of mobile application users.
        /// </summary>
        /// <param name="signUpDTO"></param>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpPost("Register/{language}")]
        [AllowAnonymous]
        [MValidationFilter]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterDTO signUpDTO)
        {
            ObjectResponse<LoginResultDTO> response = new()
            {
                Result = await _accountService.RegisterAsync(signUpDTO).ConfigureAwait(false)
            };

            if (!response.Result.ErrorMessages.IsNullOrEmpty())
            {
                var stringBuilder = new StringBuilder();

                stringBuilder.AppendJoin(',', response.Result.ErrorMessages.Select(i => i.Description));

                response.Message = stringBuilder.ToString();

                //response.Message = string.Join("\r\n", response.Result.ErrorMessages.Select(m => m.Description));
                response.StatusCode = MilvaStatusCodes.Status400BadRequest; //status kod sonradan degistirlebilir.
                response.Success = false;
            } //Bu kontroller cogalabilir. orn her hata kodu icin kendine ozel status kod yazilabilir.
            else if (response.Result.Token == null)
            {
                response.Message = _sharedLocalizer["UnknownLoginProblemMessage"];
                response.StatusCode = MilvaStatusCodes.Status400BadRequest;
                response.Success = false;
            }
            else
            {
                response.Message = _sharedLocalizer["SuccessfullyLoginMessage"];
                response.StatusCode = MilvaStatusCodes.Status200OK;
                response.Success = true;
            }
            return Ok(response);
        }

        /// <summary>
        /// Updates logged-in user's personal information.
        /// </summary>
        /// <param name="userDTO"></param>
        /// <returns></returns>
        [HttpPut]
        [Authorize(Roles = RoleNames.AppUser)]
        public async Task<IActionResult> UpdateMyAccountAsync(AppUserUpdateDTO userDTO)
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("Account", CrudOperation.Update);

            return await _accountService.UpdateAccountAsync(userDTO).ConfigureAwait(false).GetObjectResponseAsync<object>(successMessage).ConfigureAwait(false);
        }

        /// <summary>
        /// Deletes logged-in user's account.
        /// </summary>
        /// <returns></returns>
        [HttpDelete]
        [Authorize(Roles = RoleNames.AppUser)]
        public async Task<IActionResult> DeleteAccountAsync()
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("Account", CrudOperation.Delete);

            return await _accountService.DeleteAccountAsync().ConfigureAwait(false).GetObjectResponseAsync<object>(successMessage).ConfigureAwait(false);
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
        [Authorize(Roles = RoleNames.AppUser)]
        public async Task<IActionResult> SendEmailVerificationMailAsync()
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("EmailVerificationMailSent", CrudOperation.Specific);

            return await _accountService.SendEmailVerificationMailAsync().ConfigureAwait(false).GetObjectResponseAsync<object>(successMessage).ConfigureAwait(false);
        }

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
        [Authorize(Roles = RoleNames.AppUser)]
        public async Task<IActionResult> SendChangePhoneNumberMailAsync(string newPhoneNumber)
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("PhoneNumberChangeMailSent", CrudOperation.Specific);

            return await _accountService.SendChangePhoneNumberMailAsync(newPhoneNumber).ConfigureAwait(false).GetObjectResponseAsync<object>(successMessage).ConfigureAwait(false);
        }

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
        [Authorize(Roles = RoleNames.AppUser)]
        public async Task<IActionResult> SendChangeEmailMailAsync(string newEmail)
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("EmailChangeMailSent", CrudOperation.Specific);

            return await _accountService.SendChangeEmailMailAsync(newEmail).ConfigureAwait(false).GetObjectResponseAsync<object>(successMessage).ConfigureAwait(false);
        }

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
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("PasswordResetMailSent", CrudOperation.Specific);

            return await _accountService.SendResetPasswordMailAsync().ConfigureAwait(false).GetObjectResponseAsync<object>(successMessage).ConfigureAwait(false);
        }

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
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("PasswordResetMailSent", CrudOperation.Specific);

            return await _accountService.SendForgotPasswordMailAsync(email).ConfigureAwait(false).GetObjectResponseAsync<object>(successMessage).ConfigureAwait(false);
        }

        /// <summary>
        /// Sends verification code to logged-in user's phone number.
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
        [Authorize(Roles = RoleNames.AppUser)]
        public async Task<IActionResult> SendPhoneNumberVerificationMessageAsync()
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("PhoneNumberVerificationMessageSent", CrudOperation.Specific);

            return await _accountService.SendPhoneNumberVerificationMessageAsync().ConfigureAwait(false).GetObjectResponseAsync(successMessage).ConfigureAwait(false);
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
        [Authorize(Roles = RoleNames.AppUser)]
        public async Task<IActionResult> VerifyPhoneNumberAsync(string verificationCode)
            => await _accountService.VerifyPhoneNumberAsync(verificationCode).ConfigureAwait(false).GetActivityResponseAsync(_sharedLocalizer["PhoneNumberVerificationSuccessfull"],
                                                                                                                             _sharedLocalizer["AccountActivityErrorMessage"]).ConfigureAwait(false);

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
            => await _accountService.VerifyEmailAsync(emailVerificationDTO).ConfigureAwait(false).GetActivityResponseAsync(_sharedLocalizer["EmailVerificationSuccessfull"],
                                                                                                                           _sharedLocalizer["AccountActivityErrorMessage"]).ConfigureAwait(false);

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
            => await _accountService.ChangeEmailAsync(emailChangeDTO).ConfigureAwait(false).GetActivityResponseAsync(_sharedLocalizer["EmailChangeSuccessfull"],
                                                                                                                     _sharedLocalizer["AccountActivityErrorMessage"]).ConfigureAwait(false);

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
            => await _accountService.ChangePhoneNumberAsync(phoneNumberChangeDTO, true).ConfigureAwait(false).GetActivityResponseAsync(_sharedLocalizer["PhoneNumberChangeSuccessfull"],
                                                                                                                                 _sharedLocalizer["AccountActivityErrorMessage"]).ConfigureAwait(false);

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
        [Authorize(Roles = RoleNames.AppUser)]
        public async Task<IActionResult> ChangePasswordAsync([FromBody] PasswordChangeDTO passwordChangeDTO)
            => await _accountService.ChangePasswordAsync(passwordChangeDTO).ConfigureAwait(false).GetActivityResponseAsync(_sharedLocalizer["PasswordChangeSuccessfull"],
                                                                                                                           _sharedLocalizer["AccountActivityErrorMessage"]).ConfigureAwait(false);

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
            => await _accountService.ResetPasswordAsync(passwordResetDTO).ConfigureAwait(false).GetActivityResponseAsync(_sharedLocalizer["PasswordResetSuccessfull"],
                                                                                                                         _sharedLocalizer["AccountActivityErrorMessage"]).ConfigureAwait(false);

        #endregion


        #region Admin

        /// <summary>
        /// Returns all administration users for admin user.
        /// </summary>
        /// <param name="paginationParams"></param>
        /// <returns> Can be both Editors or Admins. </returns>
        [HttpPatch("Users")]
        [Authorize(Roles = RoleNames.Administrator)]
        public async Task<IActionResult> GetAllUsersAsync([FromBody] PaginationParams paginationParams)
        {
            var errorMessage = _sharedLocalizer.GetErrorMessage("User", CrudOperation.GetAll);

            var users = await _accountService.GetAllUsersAsync(paginationParams).ConfigureAwait(false);

            return users.GetPaginationResponse(_defaultSucccessMessage, errorMessage);
        }

        /// <summary>
        /// Returns one administration user according to <paramref name="userId"/> for admin user.
        /// </summary>
        /// <param name="userId"></param>
        /// <returns> Can be both Editor or Admin. </returns>
        [HttpGet("Users/User/{userId}")]
        [Authorize(Roles = RoleNames.Administrator)]
        public async Task<IActionResult> GetUserByIdAsync(ObjectId userId)
        {
            var errorMessage = _sharedLocalizer.GetErrorMessage("User", CrudOperation.GetById);

            var user = await _accountService.GetUserByIdAsync(userId).ConfigureAwait(false);

            return user.GetObjectResponse(_defaultSucccessMessage, errorMessage);
        }

        /// <summary>
        /// Creates one administration user according to <paramref name="userDTO"/>.
        /// </summary>
        /// <param name="userDTO"></param>
        /// <returns> Can be both Editors or Admins. </returns>
        [HttpPost("Users/User")]
        [Authorize(Roles = RoleNames.Administrator)]
        public async Task<IActionResult> CreateUserAsync([FromBody] MilvaMongoTemplateUserCreateDTO userDTO)
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("User", CrudOperation.Add);

            return await _accountService.CreateUserAsync(userDTO).ConfigureAwait(false).GetObjectResponseAsync(successMessage);
        }

        /// <summary>
        /// Updates one administration user according to <paramref name="userDTO"/>.
        /// </summary>
        /// <param name="userDTO"></param>
        /// <returns> Created user id. </returns>
        [HttpPut("Users/User")]
        [Authorize(Roles = RoleNames.Administrator)]
        public async Task<IActionResult> UpdateUserAsync([FromBody] MilvaMongoTemplateUserUpdateDTO userDTO)
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("User", CrudOperation.Update);

            return await _accountService.UpdateUserAsync(userDTO).ConfigureAwait(false).GetObjectResponseAsync<object>(successMessage).ConfigureAwait(false);
        }

        /// <summary>
        /// Deletes one administration user according to <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId"></param>
        /// <returns> Created user id. </returns>
        [HttpDelete("Users/User/{userId}")]
        [Authorize(Roles = RoleNames.Administrator)]
        public async Task<IActionResult> DeleteUserAsync(ObjectId userId)
        {
            var successMessage = _sharedLocalizer.GetSuccessMessage("User", CrudOperation.Delete);

            return await _accountService.DeleteUserAsync(userId).ConfigureAwait(false).GetObjectResponseAsync<object>(successMessage).ConfigureAwait(false);
        }

        /// <summary>
        /// Returns all obk app roles for combobox.
        /// </summary>
        /// <returns></returns>
        [HttpGet("Roles")]
        [Authorize(Roles = RoleNames.Administrator)]
        public async Task<IActionResult> GetRolesAsync()
        {
            var errorMessage = _sharedLocalizer.GetErrorMessage("ObkRole", CrudOperation.GetAll);

            var roles = await _accountService.GetRolesAsync().ConfigureAwait(false);

            roles.RemoveAll(i => i.Name == RoleNames.Developer || i.Name == RoleNames.AppUser);

            return roles.GetObjectResponse(_defaultSucccessMessage, errorMessage);
        }

        #endregion
    }
}
