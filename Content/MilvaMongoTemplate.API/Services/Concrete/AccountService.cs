using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using MilvaMongoTemplate.API.DTOs.AccountDTOs;
using MilvaMongoTemplate.API.Services.Abstract;
using MilvaMongoTemplate.Data.Utils;
using MilvaMongoTemplate.Entity.EmbeddedDocuments;
using Milvasoft.Caching.Redis;
using Milvasoft.Core.Abstractions;
using Milvasoft.DataAccess.MongoDB.Utils.Serializers;
using Milvasoft.Encryption.Abstract;
using Milvasoft.Identity.Abstract;
using Milvasoft.Identity.Concrete;
using Milvasoft.Identity.Concrete.Options;
using Milvasoft.Identity.TokenProvider;
using Milvasoft.Mail;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Text;

namespace MilvaMongoTemplate.API.Services.Concrete;

/// <summary>
/// Provides sign-in,sign-up and sign-out process for user.
/// </summary>
[ConfigureAwait(false)]
public class AccountService : IAccountService
{
    private enum AccountActivity
    {
        EmailVerification,
        EmailChange,
        PasswordReset,
        PhoneNumberChange
    }

    #region Fields

    private readonly Lazy<IBaseRepository<MilvaMongoTemplateUser>> _lazyUserRepository;
    private readonly Lazy<IBaseRepository<MilvaMongoTemplateRole>> _lazyRoleRepository;
    private readonly Lazy<IMilvaUserManager<MilvaMongoTemplateUser, ObjectId>> _lazyUserManager;
    private readonly Lazy<IMilvaMailSender> _lazyMilvaMailSender;
    private readonly Lazy<IRedisCacheService> _lazyRedisCacheService;
    private readonly Lazy<IMilvaLogger> _lazyMilvaLogger;
    private readonly Lazy<IMilvaEncryptionProvider> _lazyMilvaEncryptionProvider;
    private readonly ITokenManagement _tokenManagement;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly string _userName;
    private readonly MilvaIdentityOptions _options;

    /// <summary>
    /// The authentication scheme for the provider the token is associated with.
    /// </summary>
    private readonly string _loginProvider;

    /// <summary>
    /// The name of token.
    /// </summary>
    private readonly string _tokenName;

    #endregion

    /// <summary>
    /// Performs constructor injection for repository interfaces used in this service.
    /// </summary>
    /// <param name="lazyUserRepository"></param>
    /// <param name="lazyRoleRepository"></param>
    /// <param name="lazyUserManager"></param>
    /// <param name="tokenManagement"></param>
    /// <param name="localizer"></param>
    /// <param name="options"></param>
    /// <param name="httpContextAccessor"></param>
    /// <param name="lazyMilvaMailSender"></param>
    /// <param name="lazyRedisCacheService"></param>
    /// <param name="lazyMilvaLogger"></param>
    /// <param name="lazyMilvaEncryptionProvider"></param>
    public AccountService(Lazy<IBaseRepository<MilvaMongoTemplateUser>> lazyUserRepository,
                          Lazy<IBaseRepository<MilvaMongoTemplateRole>> lazyRoleRepository,
                          Lazy<IMilvaUserManager<MilvaMongoTemplateUser, ObjectId>> lazyUserManager,
                          Lazy<IMilvaMailSender> lazyMilvaMailSender,
                          Lazy<IRedisCacheService> lazyRedisCacheService,
                          Lazy<IMilvaLogger> lazyMilvaLogger,
                          Lazy<IMilvaEncryptionProvider> lazyMilvaEncryptionProvider,
                          IHttpContextAccessor httpContextAccessor,
                          ITokenManagement tokenManagement,
                          IStringLocalizer<SharedResource> localizer,
                          MilvaIdentityOptions options)
    {
        _lazyUserRepository = lazyUserRepository;
        _lazyRoleRepository = lazyRoleRepository;
        _lazyUserManager = lazyUserManager;
        _tokenManagement = tokenManagement;
        _localizer = localizer;
        _options = options;
        _lazyMilvaMailSender = lazyMilvaMailSender;
        _lazyRedisCacheService = lazyRedisCacheService;
        _lazyMilvaLogger = lazyMilvaLogger;
        _userName = httpContextAccessor.HttpContext.User.Identity.Name;
        _loginProvider = tokenManagement.LoginProvider;
        _tokenName = tokenManagement.TokenName;
        _lazyMilvaEncryptionProvider = lazyMilvaEncryptionProvider;
        _httpContextAccessor = httpContextAccessor;
    }


    /// <summary>
    /// Login for incoming user. Returns a token if login informations are valid or the user is not lockedout. Otherwise returns the error list.
    /// </summary>
    /// <param name="loginDTO"></param>
    /// <returns></returns>
    public async Task<LoginResultDTO> LoginAsync(LoginDTO loginDTO)
    {
        var user = await ValidateUserAsync(loginDTO);

        LoginResultDTO loginResult = new();

        var isAppUser = user.AppUser != null;

        loginResult.Token = GenerateTokenWithRole(user.UserName, user.Roles) as MilvaToken;

        if (isAppUser)
        {
            if (user.ValidTokens.IsNullOrEmpty())
                user.ValidTokens = new List<Token>();
            else
            {
                if (!string.IsNullOrWhiteSpace(loginDTO.MacAddress))
                {
                    var tokens = user.ValidTokens.Where(i => i.MacAddress == loginDTO.MacAddress).ToList();

                    if (!tokens.IsNullOrEmpty())
                    {
                        foreach (var token in tokens)
                        {
                            user.ValidTokens.Remove(token);
                        }
                    }
                }
            }

            user.ValidTokens.Add(new Token
            {
                TokenString = loginResult.Token.AccessToken,
                MacAddress = loginDTO.MacAddress
            });

            var updateDefiniton = Builders<MilvaMongoTemplateUser>.Update.Set(i => i.ValidTokens, user.ValidTokens);

            await _lazyUserRepository.Value.UpdateAsync(user, updateDefiniton);
        }

        return loginResult;
    }

    /// <summary>
    /// Signs out from database. Returns null if already signed out.
    /// </summary>
    /// <returns></returns>
    public async Task LogoutAsync()
    {
        CheckLoginStatus();

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, _userName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        user.ThrowIfNullObject();

        var token = GetTokenFromHeaders(_httpContextAccessor);

        if (user.ValidTokens.IsNullOrEmpty() || !user.ValidTokens.Any(i => i.TokenString == token))
            throw new MilvaUserFriendlyException(nameof(ResourceKey.AlreadyLoggedOutMessage));

        if (!user.ValidTokens.IsNullOrEmpty())
            user.ValidTokens.RemoveAll(i => i.TokenString == token);

        UpdateDefinition<MilvaMongoTemplateUser> updateDefiniton;

        updateDefiniton = Builders<MilvaMongoTemplateUser>.Update.Set(i => i.ValidTokens, user.ValidTokens)
                                                                 .Set(i => i.RefreshToken, user.RefreshToken);

        await _lazyUserRepository.Value.UpdateAsync(user, updateDefiniton);

        static string GetTokenFromHeaders(IHttpContextAccessor contextAccessor)
        {
            //If token not exists.
            var tokenExists = contextAccessor.HttpContext.Request.Headers.TryGetValue(StringKey.Authorization, out StringValues token);

            if (!tokenExists)
                return string.Empty;

            //Remove Bearer text.
            token = token.ToString().Remove(0, 7);

            return token;
        }
    }

    /// <summary>
    /// Refresh token login for all users.
    /// </summary>
    /// <param name="refreshLoginDTO"></param>
    /// <returns></returns>
    public async Task<MilvaToken> RefreshTokenLogin(RefreshLoginDTO refreshLoginDTO)
    {
        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(u => u.RefreshToken == refreshLoginDTO.RefreshToken);

        if (user == null)
            throw new MilvaUserFriendlyException(nameof(ResourceKey.TokenExpired), 31);

        var token = (MilvaToken)GenerateTokenWithRole(user.UserName, user.Roles);

        user.RefreshToken = token.RefreshToken;

        if (!user.ValidTokens.IsNullOrEmpty())
        {
            user.ValidTokens.RemoveAll(i => i.TokenString == refreshLoginDTO.OldToken);
            user.ValidTokens.Add(new Token
            {
                TokenString = token.AccessToken,
                MacAddress = refreshLoginDTO.MacAddress,
            });
        }

        var updateDefiniton = Builders<MilvaMongoTemplateUser>.Update.Set(i => i.ValidTokens, user.ValidTokens)
                                                                  .Set(i => i.RefreshToken, user.RefreshToken);

        await _lazyUserRepository.Value.UpdateAsync(user, updateDefiniton);

        return token;
    }

    /// <summary>
    /// Gets a specific personnel data from repository by token value if exsist.
    /// </summary>
    /// <returns> Logged-in user data. </returns>
    public async Task<MilvaMongoTemplateUserDTO> GetLoggedInInUserInformationAsync()
    {
        CheckLoginStatus();

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(HelperExtensions.CreateUserNameAndIsDeletedFilter(_userName),
                                                                          MilvaMongoTemplateUser.GetLoggedInUserInformationProjection);

        user.ThrowIfNullObject(nameof(ResourceKey.CannotGetSignedInUserInfo));

        List<string> userRoleNames = new();

        if (!user.Roles.IsNullOrEmpty())
            userRoleNames = (await _lazyRoleRepository.Value.GetAllAsync()).Where(r => user.Roles.Contains(r.Id.ToString())).Select(r => r.Name).ToList();

        return new MilvaMongoTemplateUserDTO
        {
            Id = user.Id,
            UserName = user.UserName,
            NameSurname = user.NameSurname,
            Email = user.Email,
            EmailConfirmed = user.EmailConfirmed,
            IdentityNumber = user.AppUser?.IdentityNumber,
            PhoneNumber = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            RoleNames = userRoleNames,
        };
    }

    #region AppUser

    /// <summary>
    /// Checks username and email existance.
    /// </summary>
    /// <param name="checkUserExistanceDTO"></param>
    /// <returns></returns>
    public async Task UserExistsAsync(CheckUserExistanceDTO checkUserExistanceDTO)
    {
        Expression<Func<MilvaMongoTemplateUser, bool>> condition = i => i.UserName == checkUserExistanceDTO.UserName;

        if (!string.IsNullOrWhiteSpace(checkUserExistanceDTO.Email))
            condition.Append(i => i.Email == checkUserExistanceDTO.Email, ExpressionType.AndAlso);

        var count = await _lazyUserRepository.Value.GetCountAsync(condition);

        if (count > 0)
            throw new MilvaUserFriendlyException(nameof(ResourceKey.UsernameOrEmailExists));
    }

    /// <summary>
    /// Sign up process for application user.
    /// If signup process is succesful,then sign in.
    /// </summary>
    /// <param name="registerDTO"></param>
    /// <returns></returns>
    public async Task<LoginResultDTO> RegisterAsync(RegisterDTO registerDTO)
    {
        await CheckEmailExistanceAsync(registerDTO.Email);

        await CheckUserExistanceAsync(registerDTO.UserName);

        MilvaMongoTemplateUser userToBeSignUp = new()
        {
            UserName = registerDTO.UserName,
            PhoneNumberConfirmed = true,
            Email = registerDTO.Email,
            Roles = new() { RoleName.AppUser }
        };

        userToBeSignUp = _lazyUserManager.Value.ConfigureForCreate(userToBeSignUp, registerDTO.Password);

        await _lazyUserRepository.Value.AddAsync(userToBeSignUp);

        var loginDTO = new LoginDTO
        {
            UserName = userToBeSignUp.UserName,
            Password = registerDTO.Password
        };

        var loginResult = await LoginAsync(loginDTO);

        if (!string.IsNullOrWhiteSpace(registerDTO.Email))
        {
            _ = SendEmailVerificationMailAsync(loginDTO.UserName);
        }

        return loginResult;
    }

    /// <summary>
    /// Deletes logged-in user's account. This operation is irreversible.
    /// </summary>
    /// <returns></returns>
    public async Task DeleteAccountAsync()
    {
        CheckLoginStatus();

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(HelperExtensions.CreateUserNameAndIsDeletedFilter(_userName), MilvaMongoTemplateUser.DeleteAccountProjection);

        user.ThrowIfNullObject();

        var updateUpdateDef = Builders<MilvaMongoTemplateUser>.Update.Set(p => p.IsDeleted, true)
                                                                  .Set(p => p.DeletionDate, DateTime.UtcNow);

        await _lazyUserRepository.Value.UpdateAsync(user, updateUpdateDef);
    }

    #endregion



    #region Account Activities 

    /// <summary>
    /// Sends email verification mail to logged-in user.
    /// </summary>
    /// <returns></returns>
    public async Task SendEmailVerificationMailAsync(string userName = "")
    {
        CheckLoginStatus(userName);

        var mailBodyKeyContentPair = PrepareMailBodyDictionary(_localizer[nameof(ResourceKey.VerificationMailTitle)],
                                                               _localizer[nameof(ResourceKey.VerificationMailBodyDescription), GlobalConstant.ApplicationSiteUrl],
                                                               _localizer[nameof(ResourceKey.VerificationMailBodyResendText), GlobalConstant.DeveloperSiteUrl],
                                                               _localizer[nameof(ResourceKey.VerificationMailBodyButtonText)]);

        await SendActivityMailAsync(mailBodyKeyContentPair, urlPath: "verify-email", AccountActivity.EmailVerification, username: userName);
    }

    /// <summary>
    /// Sends email chage mail to logged-in user.
    /// </summary>
    /// <returns></returns>
    public async Task SendChangeEmailMailAsync(string newEmail)
    {
        CheckLoginStatus();

        CheckRegex(newEmail, "Email");

        var emailFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.Email, newEmail);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(emailFilter.AddIsDeletedFilter(), MilvaMongoTemplateUser.EmailProjection);

        //Is there another user with the same email?
        bool mailExist = user != null;

        if (mailExist)
            throw new MilvaUserFriendlyException(nameof(ResourceKey.IdentityDuplicateEmail));

        var mailBodyKeyContentPair = PrepareMailBodyDictionary(_localizer[nameof(ResourceKey.EmailChangeMailTitle)],
                                                               _localizer[nameof(ResourceKey.EmailChangeMailBodyDesciption)],
                                                               _localizer[nameof(ResourceKey.EmailChangeMailBodyResendText), GlobalConstant.DeveloperSiteUrl],
                                                               _localizer[nameof(ResourceKey.EmailChangeMailBodyButtonText)]);

        await SendActivityMailAsync(mailBodyKeyContentPair, urlPath: "change-email", AccountActivity.EmailChange, newEmail);
    }

    /// <summary>
    /// Sends password reset mail to logged-in user.
    /// </summary>
    /// <returns></returns>
    public async Task SendResetPasswordMailAsync()
    {
        var mailBodyKeyContentPair = PrepareMailBodyDictionary(_localizer[nameof(ResourceKey.PasswordResetMailTitle)],
                                                               _localizer[nameof(ResourceKey.PasswordResetMailBodyDesciption)],
                                                               _localizer[nameof(ResourceKey.PasswordResetMailBodyResendText), GlobalConstant.DeveloperSiteUrl],
                                                               _localizer[nameof(ResourceKey.PasswordResetMailBodyButtonText)]);

        await SendActivityMailAsync(mailBodyKeyContentPair, urlPath: "reset-password", AccountActivity.PasswordReset);
    }

    /// <summary>
    /// Sends password reset mail to <paramref name="email"/>.
    /// </summary>
    /// <returns></returns>
    public async Task SendForgotPasswordMailAsync(string email)
    {
        var mailBodyKeyContentPair = PrepareMailBodyDictionary(_localizer[nameof(ResourceKey.PasswordResetMailTitle)],
                                                               _localizer[nameof(ResourceKey.PasswordResetMailBodyDesciption)],
                                                               _localizer[nameof(ResourceKey.PasswordResetMailBodyResendText), GlobalConstant.DeveloperSiteUrl],
                                                               _localizer[nameof(ResourceKey.PasswordResetMailBodyButtonText)]);

        var emailFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.Email, email);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(emailFilter.AddIsDeletedFilter(), MilvaMongoTemplateUser.EmailAndUserNameProjection)
                                        ?? throw new MilvaUserFriendlyException(nameof(ResourceKey.UserNotExitsWithEmail));

        await SendActivityMailAsync(mailBodyKeyContentPair, urlPath: "reset-password", AccountActivity.PasswordReset, username: user.UserName);
    }

    /// <summary>
    /// Sends verification code to phone number.
    /// <para><b> IMPORTANT INFORMATION : The message sending service has not yet been integrated. 
    ///                                   So this method will not send message to the user's gsm number.
    ///                                   Instead of returns verification code for testing. </b></para>
    /// </summary>
    /// <returns></returns>
    public async Task<string> SendPhoneNumberVerificationMessageAsync(string phoneNumber, string userName = "")
    {
        //Your code

        return string.Empty;
    }

    /// <summary>
    /// Verifies email, if <paramref name="verificationCode"/> is correct.
    /// </summary>
    /// <param name="verificationCode"></param>
    /// <returns></returns>
    public async Task VerifyPhoneNumberAsync(string verificationCode)
    {
        CheckLoginStatus();

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(HelperExtensions.CreateUserNameAndIsDeletedFilter(_userName));

        user.ThrowIfNullObject(nameof(ResourceKey.InvalidUserName));

        await VerifyPhoneNumberAsync(verificationCode, user.UserName);

        user.PhoneNumberConfirmed = true;

        var updateDefiniton = Builders<MilvaMongoTemplateUser>.Update.Set(i => i.PhoneNumberConfirmed, user.PhoneNumberConfirmed);

        await _lazyUserRepository.Value.UpdateAsync(user, updateDefiniton);
    }

    /// <summary>
    /// Verifies <paramref name="emailVerificationDTO"/>.UserName's email, if <paramref name="emailVerificationDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="emailVerificationDTO"></param>
    /// <returns></returns>
    public async Task VerifyEmailAsync(EmailVerificationDTO emailVerificationDTO)
    {
        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(HelperExtensions.CreateUserNameAndIsDeletedFilter(emailVerificationDTO.UserName));

        user.ThrowIfNullObject(nameof(ResourceKey.InvalidVerificationToken));

        var result = _lazyUserManager.Value.VerifyUserToken(user, Purpose.EmailConfirm, emailVerificationDTO.TokenString);

        if (!result)
            MilvaIdentityExceptionThrower.ThrowInvalidToken();

        user.EmailConfirmed = true;

        var updateDefiniton = Builders<MilvaMongoTemplateUser>.Update.Set(i => i.EmailConfirmed, user.EmailConfirmed);

        await _lazyUserRepository.Value.UpdateAsync(user, updateDefiniton);
    }

    /// <summary>
    /// Changes <paramref name="emailChangeDTO"/>.UserName's email with <paramref name="emailChangeDTO"/>.NewEmail, if <paramref name="emailChangeDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="emailChangeDTO"></param>
    /// <returns></returns>
    public async Task ChangeEmailAsync(EmailChangeDTO emailChangeDTO)
    {
        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(HelperExtensions.CreateUserNameAndIsDeletedFilter(emailChangeDTO.UserName));

        user.ThrowIfNullObject(nameof(ResourceKey.InvalidVerificationToken));

        var result = _lazyUserManager.Value.VerifyUserToken(user, Purpose.PasswordReset, emailChangeDTO.TokenString, emailChangeDTO.NewEmail);

        if (!result)
            MilvaIdentityExceptionThrower.ThrowInvalidToken();

        _lazyUserManager.Value.ValidateEmail(emailChangeDTO.NewEmail);

        await CheckEmailExistanceAsync(emailChangeDTO.NewEmail);

        user.Email = emailChangeDTO.NewEmail;
        user.EmailConfirmed = true;

        var updateDefiniton = Builders<MilvaMongoTemplateUser>.Update.Set(i => i.Email, user.Email)
                                                                  .Set(i => i.EmailConfirmed, user.EmailConfirmed)
                                                                  .Set(i => i.NormalizedEmail, user.NormalizedEmail);

        await _lazyUserRepository.Value.UpdateAsync(user, updateDefiniton);
    }

    /// <summary>
    /// Changes <paramref name="phoneNumberChangeDTO"/>.UserName's email 
    /// with <paramref name="phoneNumberChangeDTO"/>.NewPhoneNumber, if <paramref name="phoneNumberChangeDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="phoneNumberChangeDTO"></param>
    /// <returns></returns>
    public async Task ChangePhoneNumberAsync(PhoneNumberChangeDTO phoneNumberChangeDTO)
    {
        CheckLoginStatus();

        await CheckPhoneNumberExistanceAsync(phoneNumberChangeDTO.NewPhoneNumber);

        await VerifyPhoneNumberAsync(phoneNumberChangeDTO.VerificationCode, phoneNumberChangeDTO.NewPhoneNumber);

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, _userName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        user.ThrowIfNullObject(nameof(ResourceKey.InvalidVerificationToken));

        user.PhoneNumber = phoneNumberChangeDTO.NewPhoneNumber;
        user.PhoneNumberConfirmed = true;

        var updateDefiniton = Builders<MilvaMongoTemplateUser>.Update.Set(i => i.PhoneNumber, user.PhoneNumber)
                                                                  .Set(i => i.PhoneNumberConfirmed, user.PhoneNumberConfirmed);

        await _lazyUserRepository.Value.UpdateAsync(user, updateDefiniton);

        await _lazyRedisCacheService.Value.PerformRedisActionAsync(async () =>
        {
            await _lazyRedisCacheService.Value.RemoveAsync(HelperExtensions.CreatePhoneNumberCacheKey(phoneNumberChangeDTO.NewPhoneNumber));

        }, nameof(ResourceKey.UpdateSuccessBut), _lazyMilvaLogger.Value);
    }

    /// <summary>
    /// Resets <paramref name="passwordResetDTO"/>.UserName's password with <paramref name="passwordResetDTO"/>.NewPassword, if <paramref name="passwordResetDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="passwordResetDTO"></param>
    /// <returns></returns>
    public async Task ResetPasswordAsync(PasswordResetDTO passwordResetDTO)
    {
        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(HelperExtensions.CreateUserNameAndIsDeletedFilter(passwordResetDTO.UserName));

        user.ThrowIfNullObject(nameof(ResourceKey.InvalidUserName));

        var result = _lazyUserManager.Value.VerifyUserToken(user, Purpose.PasswordReset, passwordResetDTO.TokenString);

        if (!result)
            MilvaIdentityExceptionThrower.ThrowInvalidToken();

        _lazyUserManager.Value.ValidateAndSetPasswordHash(user, passwordResetDTO.NewPassword);

        user.ValidTokens.Clear();

        var updateDefiniton = Builders<MilvaMongoTemplateUser>.Update.Set(i => i.PasswordHash, user.PasswordHash)
                                                                  .Set(i => i.ValidTokens, user.ValidTokens);

        await _lazyUserRepository.Value.UpdateAsync(user, updateDefiniton);

    }

    /// <summary>
    /// Changes <paramref name="passwordChangeDTO"/>.UserName's <paramref name="passwordChangeDTO"/>.OldPassword with <paramref name="passwordChangeDTO"/>.NewPassword.
    /// </summary>
    /// <param name="passwordChangeDTO"></param>
    /// <returns></returns>
    public async Task ChangePasswordAsync(PasswordChangeDTO passwordChangeDTO)
    {
        CheckLoginStatus();

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(HelperExtensions.CreateUserNameAndIsDeletedFilter(_userName));

        user.ThrowIfNullObject(nameof(ResourceKey.InvalidUserName));

        var isCorrect = _lazyUserManager.Value.CheckPassword(user, passwordChangeDTO.OldPassword);

        if (!isCorrect)
            MilvaIdentityExceptionThrower.ThrowPasswordMismatch();

        _lazyUserManager.Value.ValidateAndSetPasswordHash(user, passwordChangeDTO.NewPassword);

        var updateDefiniton = Builders<MilvaMongoTemplateUser>.Update.Set(i => i.PasswordHash, user.PasswordHash);

        await _lazyUserRepository.Value.UpdateAsync(user, updateDefiniton);
    }

    #endregion


    #region Admin

    /// <summary>
    /// Returns all users as paginated. You can transport data to modal from here.
    /// </summary>
    /// <param name="paginationParams"></param>
    /// <returns></returns>
    public async Task<PaginationDTO<MilvaMongoTemplateUserDTO>> GetAllUsersAsync(PaginationParams paginationParams)
    {
        var appUserFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.AppUser, null);

        var (entities, pageCount, totalDataCount) = await _lazyUserRepository.Value.GetAsPaginatedAsync(paginationParams.PageIndex,
                                                                                              paginationParams.RequestedItemCount,
                                                                                              paginationParams.OrderByProps,
                                                                                              filterDefinition: Builders<MilvaMongoTemplateUser>.Filter.And(appUserFilter.AddIsDeletedFilter()),
                                                                                              projectExpression: MilvaMongoTemplateUser.GetUserProjection);

        var allRoles = await _lazyRoleRepository.Value.GetAllAsync(projectExpression: MilvaMongoTemplateRole.NameProjection);

        return new PaginationDTO<MilvaMongoTemplateUserDTO>
        {
            DTOList = await entities.CheckListAsync(f => entities.Select(async user => new MilvaMongoTemplateUserDTO
            {
                Id = user.Id,
                UserName = user.UserName,
                NameSurname = user.NameSurname,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                RoleNames = !user.Roles.IsNullOrEmpty()
                           ? allRoles.Where(r => user.Roles.Contains(r.Id.ToString())).Select(i => i.Name).ToList()
                           : null,
                CreationDate = user.CreationDate,
                LastModificationDate = user.LastModificationDate,
            })),
            PageCount = pageCount,
            TotalDataCount = totalDataCount
        };

    }

    /// <summary>
    /// Return single user by <paramref name="userId"/>.
    /// </summary>
    /// <param name="userId"></param>
    /// <returns></returns>
    public async Task<MilvaMongoTemplateUserDTO> GetUserByIdAsync(ObjectId userId)
    {
        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(HelperExtensions.CreateIdAndIsDeletedFilter(userId), MilvaMongoTemplateUser.GetUserProjection);

        user.ThrowIfNullObject();

        var roles = (await _lazyRoleRepository.Value.GetAllAsync(projectExpression: MilvaMongoTemplateRole.NameProjection)).Where(r => user.Roles.Contains(r.Id.ToString()));

        return user.CheckObject(f => new MilvaMongoTemplateUserDTO
        {
            Id = user.Id,
            UserName = user.UserName,
            NameSurname = user.NameSurname,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            RoleNames = !user.Roles.IsNullOrEmpty()
                            ? roles.Select(i => i.Name).ToList()
                            : null,
            CreationDate = user.CreationDate,
            LastModificationDate = user.LastModificationDate,
        });
    }

    /// <summary>
    /// Creates user according to <paramref name="userDTO"/> by admin.
    /// </summary>
    /// <param name="userDTO"></param>
    /// <returns></returns>
    public async Task<ObjectId> CreateUserAsync(MilvaMongoTemplateUserCreateDTO userDTO)
    {
        MilvaMongoTemplateUser user = new()
        {
            Id = ObjectId.GenerateNewId(),
            UserName = userDTO.UserName,
            Email = userDTO.Email,
            NameSurname = (EncryptedString)userDTO.NameSurname,
            PhoneNumber = userDTO.PhoneNumber
        };

        await CheckUserExistanceAsync(user.UserName);

        _lazyUserManager.Value.ValidateUser(user);

        var allRoles = await _lazyRoleRepository.Value.GetAllAsync(projectExpression: MilvaMongoTemplateRole.NameProjection);

        var roles = allRoles.Where(r => userDTO.Roles.Contains(r.Id));

        if (roles.IsNullOrEmpty())
            throw new MilvaUserFriendlyException(nameof(ResourceKey.AtLeastSelectOneRole));

        user = _lazyUserManager.Value.ConfigureForCreate(user, userDTO.Password);

        user.Roles = roles.Select(r => r.Name).ToList();

        await _lazyUserRepository.Value.AddAsync(user);

        return user.Id;
    }

    /// <summary>
    /// Updates user according to <paramref name="userDTO"/> by admin.
    /// </summary>
    /// <param name="userDTO"></param>
    /// <returns></returns>
    public async Task UpdateUserAsync(MilvaMongoTemplateUserUpdateDTO userDTO)
    {
        var userIdFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.Id, userDTO.Id);

        var toBeUpdatedUser = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(HelperExtensions.CreateIdAndIsDeletedFilter(userDTO.Id));

        toBeUpdatedUser.ThrowIfNullObject();

        bool initializeUpdate = false;

        if (!string.IsNullOrWhiteSpace(userDTO.NewNameSurname))
        {
            toBeUpdatedUser.NameSurname = (EncryptedString)userDTO.NewNameSurname;
            initializeUpdate = true;
        }

        if (!userDTO.NewRoles.IsNullOrEmpty())
        {
            var allRoles = await _lazyRoleRepository.Value.GetAllAsync(projectExpression: MilvaMongoTemplateRole.NameProjection);

            var newRoles = allRoles.Where(r => userDTO.NewRoles.Contains(r.Id)).Select(r => r.Name.ToString()).ToList();

            if (newRoles.IsNullOrEmpty())
                throw new MilvaUserFriendlyException(nameof(ResourceKey.AtLeastSelectOneRole));

            toBeUpdatedUser.Roles = newRoles;
        }

        if (!string.IsNullOrWhiteSpace(userDTO.NewPassword))
        {
            _lazyUserManager.Value.ValidateAndSetPasswordHash(toBeUpdatedUser, userDTO.NewPassword);
        }

        if (!string.IsNullOrWhiteSpace(userDTO.NewEmail))
        {
            var token = _lazyUserManager.Value.GenerateUserToken(toBeUpdatedUser, Purpose.EmailChange, userDTO.NewEmail);

            await ChangeEmailAsync(new EmailChangeDTO
            {
                UserName = toBeUpdatedUser.UserName,
                NewEmail = userDTO.NewEmail,
                TokenString = token
            });
        }

        if (!string.IsNullOrWhiteSpace(userDTO.NewPhoneNumber))
        {
            var phoneNumber = userDTO.NewPhoneNumber;

            toBeUpdatedUser.PhoneNumber = userDTO.NewPhoneNumber;
            toBeUpdatedUser.PhoneNumberConfirmed = false;
        }

        if (initializeUpdate)
        {
            toBeUpdatedUser.LastModificationDate = DateTime.UtcNow;

            await _lazyUserRepository.Value.UpdateAsync(toBeUpdatedUser);
        }

    }

    /// <summary>
    /// Deletes user by <paramref name="userId"/> by admin.
    /// </summary>
    /// <param name="userId"></param>
    /// <returns></returns>
    public async Task DeleteUserAsync(ObjectId userId)
    {
        var toBeDeletedUser = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(HelperExtensions.CreateIdAndIsDeletedFilter(userId));

        toBeDeletedUser.ThrowIfNullObject();

        if (toBeDeletedUser.AppUser != null)
            throw new MilvaUserFriendlyException(nameof(ResourceKey.CannotDeleteAppUser));

        if (toBeDeletedUser.UserName == DataSeed.AdminUserName)
            throw new MilvaUserFriendlyException(nameof(ResourceKey.CannotDeleteDefaultAdminUser));

        await _lazyUserRepository.Value.DeleteAsync(toBeDeletedUser.Id);
    }

    /// <summary>
    /// Returns all OpsiyonCustomer app roles.
    /// </summary>
    /// <returns></returns>
    public async Task<List<MilvaMongoTemplateRoleDTO>> GetRolesAsync()
    {
        var roles = await _lazyRoleRepository.Value.GetAllAsync(projectExpression: MilvaMongoTemplateRole.NameProjection);

        return roles.CheckList(f => roles.Select(r => new MilvaMongoTemplateRoleDTO
        {
            Id = r.Id,
            Name = r.Name
        }));
    }

    #endregion


    #region Private Helper Methods

    /// <summary>
    /// Defines token expired date.
    /// </summary>
    /// <returns></returns>
    private static DateTime GetTokenExpiredDate() => DateTime.UtcNow.AddDays(1);

    /// <summary>
    /// If <paramref name="identityResult"/> is not succeeded throwns <see cref="MilvaUserFriendlyException"/>.
    /// </summary>
    /// <param name="identityResult"></param>
    public void ThrowErrorMessagesIfNotSuccess(IdentityResult identityResult)
    {
        if (!identityResult.Succeeded)
        {
            var stringBuilder = new StringBuilder();

            stringBuilder.AppendJoin(',', identityResult.Errors.Select(i => i.Description));
            throw new MilvaUserFriendlyException(stringBuilder.ToString());
        }
    }

    /// <summary>
    /// Validating user to login.
    /// </summary>
    /// <param name="loginDTO"></param>
    /// <returns></returns>
    private async Task<MilvaMongoTemplateUser> ValidateUserAsync(LoginDTO loginDTO)
    {
        MilvaMongoTemplateUser user = new();

        #region Common Validation 

        if (loginDTO.UserName == null)
            throw new MilvaUserFriendlyException(nameof(ResourceKey.PleaseEnterUsername));

        if (loginDTO.UserName != null)
        {
            user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(i => i.UserName == loginDTO.UserName);

            bool userNotFound = user == null || user.IsDeleted;

            if (userNotFound)
                throw new MilvaUserFriendlyException(nameof(ResourceKey.InvalidLogin), MilvaStatusCodes.Status401Unauthorized);
        }

        var userLocked = _lazyUserManager.Value.IsLockedOut(user);

        //If the user is locked out and the unlock date has passed.
        if (userLocked && DateTime.UtcNow > user.LockoutEnd.Value.DateTime)
        {
            //We reset the duration of the locked user.
            _lazyUserManager.Value.ConfigureLockout(user, false);

            userLocked = false;
        }

        if (userLocked)
            ThrowIfLocked(user.LockoutEnd.Value.DateTime);

        var isPasswordTrue = _lazyUserManager.Value.CheckPassword(user, loginDTO.Password);

        if (!isPasswordTrue)
        {
            _lazyUserManager.Value.ConfigureLockout(user, true);

            var updateDefiniton = Builders<MilvaMongoTemplateUser>.Update.Set(i => i.AccessFailedCount, user.AccessFailedCount)
                                                                         .Set(i => i.LockoutEnd, user.LockoutEnd);

            await _lazyUserRepository.Value.UpdateAsync(user, updateDefiniton);

            if (_lazyUserManager.Value.IsLockedOut(user))
                ThrowIfLocked(user.LockoutEnd.Value.DateTime);

            int accessFailedCountLimit = 5;

            throw new MilvaUserFriendlyException(nameof(ResourceKey.LockWarning), exceptionObjects: accessFailedCountLimit - user.AccessFailedCount);
        }

        #endregion

        return user;

        void ThrowIfLocked(DateTime lockoutEnd)
        {
            var remainingLockoutEnd = lockoutEnd - DateTime.UtcNow;

            var reminingLockoutEndString = remainingLockoutEnd.Hours > 0
                                            ? _localizer[nameof(ResourceKey.Hours), remainingLockoutEnd.Hours]
                                            : remainingLockoutEnd.Minutes > 0
                                                 ? _localizer[nameof(ResourceKey.Minutes), remainingLockoutEnd.Minutes]
                                                 : _localizer[nameof(ResourceKey.Seconds), remainingLockoutEnd.Seconds];

            throw new MilvaUserFriendlyException(nameof(ResourceKey.Locked), reminingLockoutEndString);
        }
    }

    /// <summary>
    /// If Authentication is successful, JWT tokens are generated.
    /// </summary>
    public virtual IToken GenerateTokenWithRole(string username, IList<string> roles)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        //Kullanıcıya ait roller Tokene Claim olarak ekleniyor
        var claimsIdentityList = new ClaimsIdentity(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        claimsIdentityList.AddClaim(new Claim(ClaimTypes.Name, username));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = claimsIdentityList,
            //Issuer = _tokenManagement.Issuer,
            //Audience = _tokenManagement.Audience,
            //Expires = GetTokenExpiredDate(),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_tokenManagement.Secret)), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);//Token Üretimi

        return new MilvaToken
        {
            AccessToken = tokenHandler.WriteToken(token),
            Expiration = GetTokenExpiredDate(),
            RefreshToken = IdentityHelpers.CreateRefreshToken()
        };
    }

    /// <summary>
    /// If Authentication is successful, JWT tokens are generated.
    /// </summary>
    /// <param name="username"></param>
    /// <param name="roles"></param>
    /// <param name="isAppUser"></param>
    public IToken GenerateToken(string username, IList<string> roles, bool isAppUser)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var claimsIdentityList = new ClaimsIdentity(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        claimsIdentityList.AddClaim(new Claim(ClaimTypes.Name, username));

        var tokenExpiredDate = isAppUser ? DateTime.Now.AddHours(3) : DateTime.Now.AddDays(1);

        //if (!isAppUser)
        //    claimsIdentityList.AddClaim(new Claim(ClaimTypes.Expired, value: tokenExpiredDate.ToString()));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = claimsIdentityList,
            Issuer = _tokenManagement.Issuer,
            Audience = _tokenManagement.Audience,
            Expires = tokenExpiredDate,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_tokenManagement.Secret)), SecurityAlgorithms.HmacSha256Signature)
        };

        //if (!isAppUser)
        //    tokenDescriptor.Expires = tokenExpiredDate;

        var token = tokenHandler.CreateToken(tokenDescriptor);

        return new MilvaToken
        {
            AccessToken = tokenHandler.WriteToken(token),
            Expiration = tokenExpiredDate,
            RefreshToken = IdentityHelpers.CreateRefreshToken()
        };
    }

    /// <summary>
    /// Generates 6-digit verification code.
    /// </summary>
    /// <returns></returns>
    private static string GenerateVerificationCode()
    {
        Random rand = new();

        List<int> codeList = new();

        string verificationCode = "";

        for (int index = 0; index < 6; index++)
        {
            codeList.Add(rand.Next(1, 9));

            verificationCode += codeList.ElementAt(index).ToString();
        }
        return verificationCode;
    }

    /// <summary>
    /// <para> Please add items to <paramref name="values"/> with this sorting; </para>
    ///          <para> - Mail Title         </para>
    ///          <para> - Body Title         </para>
    ///          <para> - Body Description   </para>
    ///          <para> - Body Button Text   </para>
    ///          <para> - Body Resend Text   </para>
    ///          <para> - Body Bottom Text   </para>
    /// </summary>
    /// <param name="values"></param>
    /// <returns></returns>
    private static Dictionary<string, string> PrepareMailBodyDictionary(params string[] values)
    {
        var dic = new Dictionary<string, string>
            {
                { "~MailTitle", "" },
                { "~BodyTitle", "" },
                { "~BodyDescription", "" },
                { "~BodyButtonText", "" },
                { "~BodyResendText", "" },
                { "~BodyBottomText", "" },
            };

        int i = 0;
        foreach (var item in dic)
        {
            dic[item.Key] = values[i];
            i++;
        }

        return dic;
    }

    /// <summary>
    /// Sends email to logged-in user's email.
    /// Please make sure <paramref name="localizedMailBodyContents"/> dictionary parameter taken from <see cref="PrepareMailBodyDictionary(string[])"/>.
    /// </summary>
    /// <param name="localizedMailBodyContents"></param>
    /// <param name="urlPath"></param>
    /// <param name="accountActivity"></param>
    /// <param name="newInfo"> Could be new phone number or new email. </param>
    /// <param name="username"></param>
    /// <returns></returns>
    private async Task SendActivityMailAsync(Dictionary<string, string> localizedMailBodyContents,
                                             string urlPath,
                                             AccountActivity accountActivity,
                                             string newInfo = null,
                                             string username = null)
    {
        var uName = string.IsNullOrWhiteSpace(username) ? _userName : username;

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, uName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter(), MilvaMongoTemplateUser.SendActivityMailProjection);

        user.ThrowIfNullObject();

        if (string.IsNullOrWhiteSpace(user.Email))
        {
            if (accountActivity == AccountActivity.EmailChange)
            {
                if (string.IsNullOrWhiteSpace(newInfo))
                {
                    throw new MilvaUserFriendlyException(nameof(ResourceKey.IdentityInvalidEmail));
                }
                else user.Email = newInfo;
            }
            else throw new MilvaUserFriendlyException(nameof(ResourceKey.UserHaventEmail));
        }

        string token = accountActivity switch
        {
            AccountActivity.EmailVerification => _lazyUserManager.Value.GenerateUserToken(user, Purpose.EmailConfirm),
            AccountActivity.EmailChange => _lazyUserManager.Value.GenerateUserToken(user, Purpose.EmailChange, newInfo),
            AccountActivity.PasswordReset => _lazyUserManager.Value.GenerateUserToken(user, Purpose.PasswordReset),
            _ => throw new MilvaUserFriendlyException(nameof(ResourceKey.InvalidOperation)),
        };

        string additionalQueryParameter = newInfo != null ? $"&email={newInfo}" : "";

        var confirmationUrl = $"{GlobalConstant.ApplicationSiteUrl}/{urlPath}?userName={uName}{additionalQueryParameter}&token={Convert.ToBase64String(Encoding.UTF8.GetBytes(token))}";

        var htmlContent = await File.ReadAllTextAsync(Path.Combine(GlobalConstant.RootPath, "StaticFiles", "HTML", "mail_content.html"));

        foreach (var localizedMailBodyContent in localizedMailBodyContents)
            htmlContent = htmlContent.Replace(localizedMailBodyContent.Key, localizedMailBodyContent.Value);

        htmlContent = htmlContent.Replace("~ButtonLink", confirmationUrl);
    }

    /// <summary>
    /// Verifies phonen number, if <paramref name="verificationCode"/> is correct.
    /// </summary>
    /// <param name="verificationCode"></param>
    /// <param name="phoneNumber"></param>
    /// <returns></returns>
    private async Task VerifyPhoneNumberAsync(string verificationCode, string phoneNumber)
    {
        if (string.IsNullOrWhiteSpace(verificationCode))
            throw new MilvaUserFriendlyException(ResourceKey.WrongPhoneNumberVerificationCode);

        var cacheKey = HelperExtensions.CreatePhoneNumberCacheKey(phoneNumber);

        var verificationCodeInCache = string.Empty;

        await _lazyRedisCacheService.Value.PerformRedisActionAsync(async () =>
        {
            var keyExists = await _lazyRedisCacheService.Value.KeyExistsAsync(cacheKey);

            if (!keyExists)
                throw new MilvaUserFriendlyException(nameof(ResourceKey.ThereIsNoSavedVerificationCode));

            verificationCodeInCache = await _lazyRedisCacheService.Value.GetAsync(cacheKey);

        }, nameof(ResourceKey.AnErrorOccured), _lazyMilvaLogger.Value);

        if (verificationCode != verificationCodeInCache || string.IsNullOrWhiteSpace(verificationCodeInCache))
            throw new MilvaUserFriendlyException(nameof(ResourceKey.WrongPhoneNumberVerificationCode));
    }

    /// <summary>
    /// Regex check for action parameter.
    /// </summary>
    /// <param name="input"></param>
    /// <param name="propName"></param>
    private void CheckRegex(string input, string propName)
    {
        var localizedPattern = _localizer[$"RegexPattern{propName}"];

        if (!input.MatchRegex(_localizer[localizedPattern]))
        {
            var exampleFormat = _localizer[$"RegexExample{propName}"];
            throw new MilvaUserFriendlyException("RegexErrorMessage", _localizer[$"Localized{propName}"], exampleFormat);
        }
    }

    /// <summary>
    /// Cheks <see cref="_userName"/>. If is null or empty throwns <see cref="MilvaUserFriendlyException"/>. Otherwise does nothing.
    /// </summary>
    private string CheckLoginStatus(string username = "")
    {
        if (string.IsNullOrWhiteSpace(_userName) && string.IsNullOrWhiteSpace(username))
            throw new MilvaUserFriendlyException(nameof(ResourceKey.CannotGetSignedInUserInfo));

        return username ?? _userName;
    }

    /// <summary>
    /// Checks phone number existance.
    /// </summary>
    /// <param name="phoneNumber"></param>
    /// <returns></returns>
    /// <exception cref="MilvaUserFriendlyException"></exception>
    private async Task CheckPhoneNumberExistanceAsync(string phoneNumber)
    {
        var userCount = await _lazyUserRepository.Value.GetCountAsync(i => !i.IsDeleted && i.PhoneNumber == phoneNumber);

        if (userCount > 0)
            throw new MilvaUserFriendlyException(nameof(ResourceKey.PhoneNumberExists));
    }

    /// <summary>
    /// Checks email existance.
    /// </summary>
    /// <param name="email"></param>
    /// <returns></returns>
    /// <exception cref="MilvaUserFriendlyException"></exception>
    private async Task CheckEmailExistanceAsync(string email)
    {
        if (_options.User.RequireUniqueEmail)
        {
            var userCount = await _lazyUserRepository.Value.GetCountAsync(i => !i.IsDeleted && i.Email == email);

            if (userCount > 0)
                MilvaIdentityExceptionThrower.ThrowDuplicateEmail();
        }
    }

    /// <summary>
    /// Checks username existance.
    /// </summary>
    /// <param name="userName"></param>
    /// <returns></returns>
    /// <exception cref="MilvaUserFriendlyException"></exception>
    private async Task CheckUserExistanceAsync(string userName)
    {
        var userCount = await _lazyUserRepository.Value.GetCountAsync(i => !i.IsDeleted && i.UserName == userName);

        if (userCount > 0)
            MilvaIdentityExceptionThrower.ThrowDuplicateUserName();
    }

    #endregion
}
