using Microsoft.AspNetCore.Identity;
using MilvaMongoTemplate.API.DTOs;
using MilvaMongoTemplate.API.DTOs.AccountDTOs;
using Milvasoft.Helpers.Models;
using MongoDB.Bson;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace MilvaMongoTemplate.API.Services.Common.Abstract
{
    /// <summary>
    /// <para><b>EN:</b> The class in which user transactions are entered and exited</para>
    /// <para><b>TR:</b> Kullanıcı işlemlerinin giriş-çıkış işlemlerinin yapıldığı sınıf</para>
    /// </summary>
    public interface IAccountService
    {
        /// <summary>
        /// Signs in for incoming user. Returns a token if login informations are valid or the user is not lockedout. Otherwise returns the error list.
        /// </summary>
        /// <param name="loginDTO"></param>
        /// <returns></returns>
        Task<LoginResultDTO> LoginAsync(LoginDTO loginDTO);

        /// <summary>
        /// Refresh token login for all users.
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        Task<LoginResultDTO> RefreshTokenLogin(string refreshToken);

        /// <summary>
        /// Signs out from database. Returns null if already signed out.
        /// </summary>
        /// <returns></returns>
        Task LogoutAsync();

        /// <summary>
        /// Gets a specific personnel data from repository by token value if exsist.
        /// </summary>
        /// <returns> Logged-in user data. </returns>
        Task<MilvaMongoTemplateUserDTO> GetLoggedInInUserInformationAsync();

        #region AppUser

        /// <summary>
        /// Sign up process for application user.
        /// If signup process is succesful,then sign in.
        /// </summary>
        /// <param name="userSignUpDTO"></param>
        /// <returns></returns>
        Task<LoginResultDTO> RegisterAsync(RegisterDTO userSignUpDTO);

        /// <summary>
        /// Updates logged-in user's personal information.
        /// </summary>
        /// <param name="userDTO"></param>
        /// <returns></returns>
        Task UpdateAccountAsync(AppUserUpdateDTO userDTO);

        /// <summary>
        /// Deletes logged-in user's account. This operation is irreversible.
        /// </summary>
        /// <returns></returns>
        Task DeleteAccountAsync();

        #endregion


        #region Admin

        /// <summary>
        /// Returns all users as paginated.
        /// </summary>
        /// <param name="paginationParams"></param>
        /// <returns></returns>
        Task<PaginationDTO<MilvaMongoTemplateUserDTO>> GetAllUsersAsync(PaginationParams paginationParams);

        /// <summary>
        /// Return single user by <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        Task<MilvaMongoTemplateUserDTO> GetUserByIdAsync(ObjectId userId);

        /// <summary>
        /// Creates user according to <paramref name="userDTO"/> by admin.
        /// </summary>
        /// <param name="userDTO"></param>
        /// <returns></returns>
        Task<ObjectId> CreateUserAsync(MilvaMongoTemplateUserCreateDTO userDTO);

        /// <summary>
        /// Updates user according to <paramref name="userDTO"/> by admin.
        /// </summary>
        /// <param name="userDTO"></param>
        /// <returns></returns>
        Task UpdateUserAsync(MilvaMongoTemplateUserUpdateDTO userDTO);

        /// <summary>
        /// Deletes user by <paramref name="userId"/> by admin.
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        Task DeleteUserAsync(ObjectId userId);

        /// <summary>
        /// Returns all MilvaMongoTemplate app roles.
        /// </summary>
        /// <returns></returns>
        Task<List<MilvaMongoTemplateRoleDTO>> GetRolesAsync();

        #endregion


        #region Account Activities 

        /// <summary>
        /// Sends email verification mail to logged-in user.
        /// </summary>
        /// <returns></returns>
        Task SendEmailVerificationMailAsync(string userName = "");

        /// <summary>
        /// Sends phone number change mail to logged-in user.
        /// </summary>
        /// <returns></returns>
        Task SendChangePhoneNumberMailAsync(string newPhoneNumber);

        /// <summary>
        /// Sends email chage mail to logged-in user.
        /// </summary>
        /// <returns></returns>
        Task SendChangeEmailMailAsync(string newEmail);

        /// <summary>
        /// Sends password reset mail to logged-in user.
        /// </summary>
        /// <returns></returns>
        Task SendResetPasswordMailAsync();

        /// <summary>
        /// Sends password reset mail to <paramref name="email"/>.
        /// </summary>
        /// <returns></returns>
        Task SendForgotPasswordMailAsync(string email);

        /// <summary>
        /// Sends verification code to phone number.
        /// <para><b> IMPORTANT INFORMATION : The message sending service has not yet been integrated. 
        ///                                   So this method will not send message to the user's gsm number.
        ///                                   Instead of returns verification code for testing. </b></para>
        /// </summary>
        /// <returns></returns>
        Task<string> SendPhoneNumberVerificationMessageAsync();

        /// <summary>
        /// Verifies email, if <paramref name="verificationCode"/> is correct.
        /// </summary>
        /// <param name="verificationCode"></param>
        /// <returns></returns>
        Task<IdentityResult> VerifyPhoneNumberAsync(string verificationCode);

        /// <summary>
        /// Verifies <paramref name="emailVerificationDTO"/>.UserName's email, if <paramref name="emailVerificationDTO"/>.TokenString is valid.
        /// </summary>
        /// <param name="emailVerificationDTO"></param>
        /// <returns></returns>
        Task<IdentityResult> VerifyEmailAsync(EmailVerificationDTO emailVerificationDTO);

        /// <summary>
        /// Changes <paramref name="emailChangeDTO"/>.UserName's email with <paramref name="emailChangeDTO"/>.NewEmail, if <paramref name="emailChangeDTO"/>.TokenString is valid.
        /// </summary>
        /// <param name="emailChangeDTO"></param>
        /// <returns></returns>
        Task<IdentityResult> ChangeEmailAsync(EmailChangeDTO emailChangeDTO);

        /// <summary>
        /// Changes <paramref name="phoneNumberChangeDTO"/>.UserName's phone number. 
        /// with <paramref name="phoneNumberChangeDTO"/>.NewPhoneNumber, if <paramref name="phoneNumberChangeDTO"/>.TokenString is valid.
        /// </summary>
        /// <param name="phoneNumberChangeDTO"></param>
        /// <returns></returns>
        Task<IdentityResult> ChangePhoneNumberAsync(PhoneNumberChangeDTO phoneNumberChangeDTO);

        /// <summary>
        /// Resets <paramref name="passwordResetDTO"/>.UserName's password with <paramref name="passwordResetDTO"/>.NewPassword, if <paramref name="passwordResetDTO"/>.TokenString is valid.
        /// </summary>
        /// <param name="passwordResetDTO"></param>
        /// <returns></returns>
        Task<IdentityResult> ResetPasswordAsync(PasswordResetDTO passwordResetDTO);

        /// <summary>
        /// Changes <paramref name="passwordChangeDTO"/>.UserName's <paramref name="passwordChangeDTO"/>.OldPassword with <paramref name="passwordChangeDTO"/>.NewPassword.
        /// </summary>
        /// <param name="passwordChangeDTO"></param>
        /// <returns></returns>
        Task<IdentityResult> ChangePasswordAsync(PasswordChangeDTO passwordChangeDTO);

        #endregion
    }
}
