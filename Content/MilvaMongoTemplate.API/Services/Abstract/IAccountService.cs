using MilvaMongoTemplate.API.DTOs.AccountDTOs;
using Milvasoft.Identity.Concrete;

namespace MilvaMongoTemplate.API.Services.Abstract;

/// <summary>
/// <para><b>EN:</b> The class in which user transactions are entered and exited</para>
/// <para><b>TR:</b> Kullanıcı işlemlerinin giriş-çıkış işlemlerinin yapıldığı sınıf</para>
/// </summary>
public interface IAccountService
{
    /// <summary>
    /// Login for incoming user. Returns a token if login informations are valid or the user is not lockedout. Otherwise returns the error list.
    /// </summary>
    /// <param name="loginDTO"></param>
    /// <returns></returns>
    Task<LoginResultDTO> LoginAsync(LoginDTO loginDTO);

    /// <summary>
    /// Signs out from database. Returns null if already signed out.
    /// </summary>
    /// <returns></returns>
    Task LogoutAsync();

    /// <summary>
    /// Refresh token login for all users.
    /// </summary>
    /// <param name="refreshLoginDTO"></param>
    /// <returns></returns>
    Task<MilvaToken> RefreshTokenLogin(RefreshLoginDTO refreshLoginDTO);

    /// <summary>
    /// Gets a specific personnel data from repository by token value if exsist.
    /// </summary>
    /// <returns> Logged-in user data. </returns>
    Task<MilvaMongoTemplateUserDTO> GetLoggedInInUserInformationAsync();

    #region AppUser

    /// <summary>
    /// Checks username and email existance.
    /// </summary>
    /// <param name="checkUserExistanceDTO"></param>
    /// <returns></returns>
    Task UserExistsAsync(CheckUserExistanceDTO checkUserExistanceDTO);

    /// <summary>
    /// Sign up process for application user.
    /// If signup process is succesful,then sign in.
    /// </summary>
    /// <param name="registerDTO"></param>
    /// <returns></returns>
    Task<LoginResultDTO> RegisterAsync(RegisterDTO registerDTO);

    /// <summary>
    /// Deletes logged-in user's account. This operation is irreversible.
    /// </summary>
    /// <returns></returns>
    Task DeleteAccountAsync();

    #endregion



    #region Account Activities 

    /// <summary>
    /// Sends email verification mail to logged-in user.
    /// </summary>
    /// <returns></returns>
    Task SendEmailVerificationMailAsync(string userName = "");

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
    Task<string> SendPhoneNumberVerificationMessageAsync(string phoneNumber, string userName = "");

    /// <summary>
    /// Verifies email, if <paramref name="verificationCode"/> is correct.
    /// </summary>
    /// <param name="verificationCode"></param>
    /// <returns></returns>
    Task VerifyPhoneNumberAsync(string verificationCode);

    /// <summary>
    /// Verifies <paramref name="emailVerificationDTO"/>.UserName's email, if <paramref name="emailVerificationDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="emailVerificationDTO"></param>
    /// <returns></returns>
    Task VerifyEmailAsync(EmailVerificationDTO emailVerificationDTO);

    /// <summary>
    /// Changes <paramref name="emailChangeDTO"/>.UserName's email with <paramref name="emailChangeDTO"/>.NewEmail, if <paramref name="emailChangeDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="emailChangeDTO"></param>
    /// <returns></returns>
    Task ChangeEmailAsync(EmailChangeDTO emailChangeDTO);

    /// <summary>
    /// Changes <paramref name="phoneNumberChangeDTO"/>.UserName's email 
    /// with <paramref name="phoneNumberChangeDTO"/>.NewPhoneNumber, if <paramref name="phoneNumberChangeDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="phoneNumberChangeDTO"></param>
    /// <returns></returns>
    Task ChangePhoneNumberAsync(PhoneNumberChangeDTO phoneNumberChangeDTO);

    /// <summary>
    /// Resets <paramref name="passwordResetDTO"/>.UserName's password with <paramref name="passwordResetDTO"/>.NewPassword, if <paramref name="passwordResetDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="passwordResetDTO"></param>
    /// <returns></returns>
    Task ResetPasswordAsync(PasswordResetDTO passwordResetDTO);

    /// <summary>
    /// Changes <paramref name="passwordChangeDTO"/>.UserName's <paramref name="passwordChangeDTO"/>.OldPassword with <paramref name="passwordChangeDTO"/>.NewPassword.
    /// </summary>
    /// <param name="passwordChangeDTO"></param>
    /// <returns></returns>
    Task ChangePasswordAsync(PasswordChangeDTO passwordChangeDTO);

    #endregion


    #region Admin

    /// <summary>
    /// Returns all users as paginated. You can transport data to modal from here.
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
    /// Returns all OpsiyonCustomer app roles.
    /// </summary>
    /// <returns></returns>
    Task<List<MilvaMongoTemplateRoleDTO>> GetRolesAsync();

    #endregion
}
