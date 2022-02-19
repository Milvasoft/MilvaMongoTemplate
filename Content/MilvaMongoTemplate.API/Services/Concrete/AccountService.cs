﻿using Fody;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Localization;
using Microsoft.IdentityModel.Tokens;
using MilvaMongoTemplate.API.DTOs;
using MilvaMongoTemplate.API.DTOs.AccountDTOs;
using MilvaMongoTemplate.API.Helpers.Constants;
using MilvaMongoTemplate.API.Helpers.Extensions;
using MilvaMongoTemplate.API.Services.Abstract;
using MilvaMongoTemplate.Entity.Collections;
using MilvaMongoTemplate.Localization;
using Milvasoft.Helpers;
using Milvasoft.Helpers.Caching;
using Milvasoft.Helpers.DataAccess.MongoDB.Abstract;
using Milvasoft.Helpers.DependencyInjection;
using Milvasoft.Helpers.Encryption.Concrete;
using Milvasoft.Helpers.Enums;
using Milvasoft.Helpers.Exceptions;
using Milvasoft.Helpers.Extensions;
using Milvasoft.Helpers.Identity.Abstract;
using Milvasoft.Helpers.Identity.Concrete;
using Milvasoft.Helpers.Mail;
using Milvasoft.Helpers.Models;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using ResourceKey = MilvaMongoTemplate.Localization.Resources.SharedResource;

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
    private readonly Lazy<UserManager<MilvaMongoTemplateUser>> _lazyUserManager;
    private readonly Lazy<SignInManager<MilvaMongoTemplateUser>> _lazySignInManager;
    private readonly Lazy<IMilvaMailSender> _lazyMilvaMailSender;
    private readonly Lazy<IRedisCacheService> _lazyRedisCacheService;
    private readonly Lazy<IMilvaLogger> _lazyMilvaLogger;
    private readonly Lazy<MilvaEncryptionProvider> _lazyMilvaEncryptionProvider;
    private readonly ITokenManagement _tokenManagement;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly string _userName;

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
    /// <param name="lazySignInManager"></param>
    /// <param name="tokenManagement"></param>
    /// <param name="localizer"></param>
    /// <param name="httpContextAccessor"></param>
    /// <param name="lazyMilvaMailSender"></param>
    /// <param name="lazyRedisCacheService"></param>
    /// <param name="lazyMilvaLogger"></param>
    /// <param name="lazyMilvaEncryptionProvider"></param>
    public AccountService(Lazy<IBaseRepository<MilvaMongoTemplateUser>> lazyUserRepository,
                          Lazy<IBaseRepository<MilvaMongoTemplateRole>> lazyRoleRepository,
                          Lazy<UserManager<MilvaMongoTemplateUser>> lazyUserManager,
                          Lazy<SignInManager<MilvaMongoTemplateUser>> lazySignInManager,
                          Lazy<IMilvaMailSender> lazyMilvaMailSender,
                          Lazy<IRedisCacheService> lazyRedisCacheService,
                          Lazy<IMilvaLogger> lazyMilvaLogger,
                          Lazy<MilvaEncryptionProvider> lazyMilvaEncryptionProvider,
                          IHttpContextAccessor httpContextAccessor,
                          ITokenManagement tokenManagement,
                          IStringLocalizer<SharedResource> localizer)
    {
        _lazyUserRepository = lazyUserRepository;
        _lazyRoleRepository = lazyRoleRepository;
        _lazyUserManager = lazyUserManager;
        _lazySignInManager = lazySignInManager;
        _tokenManagement = tokenManagement;
        _localizer = localizer;
        _lazyMilvaMailSender = lazyMilvaMailSender;
        _lazyRedisCacheService = lazyRedisCacheService;
        _lazyMilvaLogger = lazyMilvaLogger;
        _userName = httpContextAccessor.HttpContext.User.Identity.Name;
        _loginProvider = tokenManagement.LoginProvider;
        _tokenName = tokenManagement.TokenName;
        _lazyMilvaEncryptionProvider = lazyMilvaEncryptionProvider;
    }


    /// <summary>
    /// Signs in for incoming user. Returns a token if login informations are valid or the user is not lockedout. Otherwise returns the error list.
    /// </summary>
    /// <param name="loginDTO"></param>
    /// <returns></returns>
    public async Task<LoginResultDTO> LoginAsync(LoginDTO loginDTO)
    {
        var (user, loginResult) = await ValidateUser(loginDTO);

        if (loginResult.ErrorMessages.Count > 0)
            return loginResult;

        SignInResult signInResult = await _lazySignInManager.Value.PasswordSignInAsync(user, loginDTO.Password, true, lockoutOnFailure: true);

        //Kimlik doğrulama başarılı ise
        if (signInResult.Succeeded)
        {
            var isAppUser = user.AppUser != null;

            loginResult.Token = (MilvaToken)await GenerateTokenWithRoleAsync(user: user, isAppUser);

            return loginResult;
        }

        #region Error Handling

        //Eğer ki başarısız bir account girişi söz konusu ise AccessFailedCount kolonundaki değer +1 arttırılacaktır. 
        await _lazyUserManager.Value.AccessFailedAsync(user);

        if (signInResult.RequiresTwoFactor)
            loginResult.ErrorMessages.Add(new IdentityError { Code = "RequiresTwoFactor", Description = _localizer["RequiresTwoFactor"] });

        if (signInResult.IsNotAllowed)
            loginResult.ErrorMessages.Add(new IdentityError { Code = "NotAllowed", Description = _localizer["NotAllowed"] });

        #endregion

        return loginResult;
    }

    /// <summary>
    /// Refresh token login for all users.
    /// </summary>
    /// <param name="refreshToken"></param>
    /// <returns></returns>
    public async Task<LoginResultDTO> RefreshTokenLogin(string refreshToken)
    {
        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(u => u.RefreshToken == refreshToken);

        if (user != null)
        {
            var token = (MilvaToken)await GenerateTokenWithRoleAsync(user: user, user.AppUser != null);

            user.RefreshToken = token.RefreshToken;

            await _lazyUserManager.Value.UpdateAsync(user);

            return new LoginResultDTO
            {
                Token = token,
            };
        }
        return new LoginResultDTO
        {
            ErrorMessages = new List<IdentityError>() { new IdentityError { Code = "TokenExpired", Description = _localizer["TokenExpired"] } }
        };
    }


    /// <summary>
    /// Signs out from database. Returns null if already signed out.
    /// </summary>
    /// <returns></returns>
    public async Task LogoutAsync()
    {
        CheckLoginStatus();

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, _userName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter())
            ?? throw new MilvaUserFriendlyException(MilvaException.CannotFindEntity);

        if (await _lazyUserManager.Value.GetAuthenticationTokenAsync(user, _loginProvider, _tokenName) == null)
            throw new MilvaUserFriendlyException("AlreadyLoggedOutMessage");

        var identityResult = await _lazyUserManager.Value.RemoveAuthenticationTokenAsync(user, _loginProvider, _tokenName);

        identityResult.ThrowErrorMessagesIfNotSuccess();

        await _lazySignInManager.Value.SignOutAsync();
    }

    /// <summary>
    /// Gets a specific personnel data from repository by token value if exsist.
    /// </summary>
    /// <returns> Logged-in user data. </returns>
    public async Task<MilvaMongoTemplateUserDTO> GetLoggedInInUserInformationAsync()
    {
        CheckLoginStatus();

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, _userName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        user.ThrowIfNullObject("CannotGetSignedInUserInfo");

        List<string> userRoleNames = new();

        if (!user.Roles.IsNullOrEmpty())
            userRoleNames = (await _lazyRoleRepository.Value.GetAllAsync()).Where(r => user.Roles.Contains(r.Id.ToString())).Select(r => r.Name).ToList();

        return new MilvaMongoTemplateUserDTO
        {
            Id = user.Id,
            UserName = user.UserName,
            Name = user.Name != null ? await _lazyMilvaEncryptionProvider.Value.DecryptAsync(user.Name) : null,
            Surname = user.Surname != null ? await _lazyMilvaEncryptionProvider.Value.DecryptAsync(user.Surname) : null,
            Email = user.Email,
            EmailConfirmed = user.EmailConfirmed,
            IdentityNumber = user.AppUser != null ? user.AppUser.IdentityNumber != null ? await _lazyMilvaEncryptionProvider.Value.DecryptAsync(user.AppUser.IdentityNumber) : null : null,
            PhoneNumber = user.PhoneNumber != null ? await _lazyMilvaEncryptionProvider.Value.DecryptAsync(user.PhoneNumber) : null,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            RoleNames = userRoleNames,
        };
    }


    #region AppUser

    /// <summary>
    /// Sign up process for application user.
    /// If signup process is succesful,then sign in.
    /// </summary>
    /// <param name="registerDTO"></param>
    /// <returns></returns>
    public async Task<LoginResultDTO> RegisterAsync(RegisterDTO registerDTO)
    {
        MilvaMongoTemplateUser userToBeSignUp = new()
        {
            UserName = registerDTO.UserName,
            Email = registerDTO.Email,
            Roles = new() { "000000000000000000000003" },
            AppUser = new()
            {
            }
        };

        LoginResultDTO loginResult = new();

        var createResult = await _lazyUserManager.Value.CreateAsync(userToBeSignUp, registerDTO.Password);

        if (createResult.Succeeded)
        {
            LoginDTO loginDTO = new();
            loginDTO.UserName = userToBeSignUp.UserName;
            loginDTO.Password = registerDTO.Password;

            loginResult = await LoginAsync(loginDTO);
        }
        else
        {
            loginResult.ErrorMessages = createResult.Errors.ToList();
        }

        return loginResult;
    }

    /// <summary>
    /// Updates logged-in user's personal information.
    /// </summary>
    /// <param name="userDTO"></param>
    /// <returns></returns>
    public async Task UpdateAccountAsync(AppUserUpdateDTO userDTO)
    {
        CheckLoginStatus();

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, _userName);

        var toBeUpdatedUser = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        bool initializeUpdate = false;

        if (!string.IsNullOrEmpty(userDTO.IdentityNumber))
            toBeUpdatedUser.AppUser.IdentityNumber = await _lazyMilvaEncryptionProvider.Value.EncryptAsync(userDTO.IdentityNumber);
        else
            if (userDTO.FirsUpdate)
            throw new MilvaUserFriendlyException("");

        if (!string.IsNullOrEmpty(userDTO.NewName))
        {
            toBeUpdatedUser.Name = await _lazyMilvaEncryptionProvider.Value.EncryptAsync(userDTO.NewName);
            initializeUpdate = true;
        }

        if (!string.IsNullOrEmpty(userDTO.NewSurname))
        {
            toBeUpdatedUser.Surname = await _lazyMilvaEncryptionProvider.Value.EncryptAsync(userDTO.NewSurname);
            initializeUpdate = true;
        }

        if (!string.IsNullOrEmpty(userDTO.PhoneNumber))
        {
            toBeUpdatedUser.PhoneNumber = await _lazyMilvaEncryptionProvider.Value.EncryptAsync(userDTO.PhoneNumber);
            toBeUpdatedUser.PhoneNumberConfirmed = false;
            initializeUpdate = true;
        }

        if (initializeUpdate)
        {
            toBeUpdatedUser.LastModificationDate = DateTime.Now;

            var updateResult = await _lazyUserManager.Value.UpdateAsync(toBeUpdatedUser);

            ThrowErrorMessagesIfNotSuccess(updateResult);
        }
    }

    /// <summary>
    /// Deletes logged-in user's account. This operation is irreversible.
    /// </summary>
    /// <returns></returns>
    public async Task DeleteAccountAsync()
    {
        CheckLoginStatus();

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, _userName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter())
                        ?? throw new MilvaUserFriendlyException(MilvaException.CannotFindEntity);

        var deleteResult = await _lazyUserManager.Value.DeleteAsync(user);

        if (!deleteResult.Succeeded)
            ThrowErrorMessagesIfNotSuccess(deleteResult);
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

        var mailBodyKeyContentPair = PrepareMailBodyDictionary(_localizer["VerificationMailTitle"],
                                                               _localizer["VerificationMailBodyTitle"],
                                                               _localizer["VerificationMailBodyDescription", GlobalConstant.ApplicationSiteUrl],
                                                               _localizer["VerificationMailBodyButtonText"],
                                                               _localizer["VerificationMailBodyResendText", GlobalConstant.DeveloperSiteUrl],
                                                               _localizer["VerificationMailBodyWelcomeText"]);

        await SendActivityMailAsync(mailBodyKeyContentPair, urlPath: "verify", AccountActivity.EmailVerification);
    }

    /// <summary>
    /// Sends phone number change mail to logged-in user.
    /// </summary>
    /// <returns></returns>
    public async Task SendChangePhoneNumberMailAsync(string newPhoneNumber)
    {
        CheckLoginStatus();

        CheckRegex(newPhoneNumber, "PhoneNumber");

        var mailBodyKeyContentPair = PrepareMailBodyDictionary(_localizer["GSMChangeMailTitle"],
                                                               _localizer["GSMChangeMailBodyTitle"],
                                                               _localizer["GSMChangeMailBodyDesciption"],
                                                               _localizer["GSMChangeMailBodyButtonText"],
                                                               _localizer["GSMChangeMailBodyResendText", GlobalConstant.DeveloperSiteUrl],
                                                               _localizer["GSMChangeMailBodyWelcomeText"]);

        await SendActivityMailAsync(mailBodyKeyContentPair, urlPath: "change/phoneNumber", AccountActivity.PhoneNumberChange, newPhoneNumber);
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

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(emailFilter.AddIsDeletedFilter());

        //Is there another user with the same email?
        bool mailExist = user != null;

        if (mailExist)
            throw new MilvaUserFriendlyException("IdentityDuplicateEmail");

        var mailBodyKeyContentPair = PrepareMailBodyDictionary(_localizer["EmailChangeMailTitle"],
                                                               _localizer["EmailChangeMailBodyTitle"],
                                                               _localizer["EmailChangeMailBodyDesciption"],
                                                               _localizer["EmailChangeMailBodyButtonText"],
                                                               _localizer["EmailChangeMailBodyResendText", GlobalConstant.DeveloperSiteUrl],
                                                               _localizer["EmailChangeMailBodyWelcomeText"]);

        await SendActivityMailAsync(mailBodyKeyContentPair, urlPath: "change/email", AccountActivity.EmailChange, newEmail);
    }

    /// <summary>
    /// Sends password reset mail to logged-in user.
    /// </summary>
    /// <returns></returns>
    public async Task SendResetPasswordMailAsync()
    {
        var mailBodyKeyContentPair = PrepareMailBodyDictionary(_localizer["PasswordResetMailTitle"],
                                                               _localizer["PasswordResetMailBodyTitle"],
                                                               _localizer["PasswordResetMailBodyDesciption"],
                                                               _localizer["PasswordResetMailBodyButtonText"],
                                                               _localizer["PasswordResetMailBodyResendText", GlobalConstant.DeveloperSiteUrl],
                                                               _localizer["PasswordResetMailBodyWelcomeText"]);

        await SendActivityMailAsync(mailBodyKeyContentPair, urlPath: "reset/password", AccountActivity.PasswordReset);
    }

    /// <summary>
    /// Sends password reset mail to<paramref name="email"/>.
    /// </summary>
    /// <returns></returns>
    public async Task SendForgotPasswordMailAsync(string email)
    {
        var mailBodyKeyContentPair = PrepareMailBodyDictionary(_localizer["PasswordResetMailTitle"],
                                                               _localizer["PasswordResetMailBodyTitle"],
                                                               _localizer["PasswordResetMailBodyDesciption"],
                                                               _localizer["PasswordResetMailBodyButtonText"],
                                                               _localizer["PasswordResetMailBodyResendText", GlobalConstant.DeveloperSiteUrl],
                                                               _localizer["PasswordResetMailBodyWelcomeText"]);

        var emailFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.Email, email);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(emailFilter.AddIsDeletedFilter())
                                        ?? throw new MilvaUserFriendlyException(MilvaException.CannotFindEntity);

        await SendActivityMailAsync(mailBodyKeyContentPair, urlPath: "reset/password", AccountActivity.PasswordReset, username: user.UserName);
    }

    /// <summary>
    /// Sends verification code to logged-in user's phone number.
    /// <para><b> IMPORTANT INFORMATION : The message sending service has not yet been integrated. 
    ///                                   So this method will not send message to the user's gsm number.
    ///                                   Instead of returns verification code for testing. </b></para>
    /// </summary>
    /// <returns></returns>
    public async Task<string> SendPhoneNumberVerificationMessageAsync()
    {
        CheckLoginStatus();

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, _userName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        if (string.IsNullOrEmpty(user?.PhoneNumber))
            throw new MilvaUserFriendlyException("IdentityInvalidPhoneNumber");

        var verificationCode = GenerateVerificationCode();

        if (!_lazyRedisCacheService.Value.IsConnected())
        {
            try
            {
                await _lazyRedisCacheService.Value.ConnectAsync();
            }
            catch (Exception)
            {
                _ = _lazyMilvaLogger.Value.LogFatalAsync("Redis is not available!!", MailSubject.ShutDown);
                throw new MilvaUserFriendlyException("CannotSendMessageNow");
            }
        }

        await _lazyRedisCacheService.Value.SetAsync($"pvc_{_userName}", verificationCode, TimeSpan.FromMinutes(3));

        //Integration of sending verification code as a message can be added here..
        //So for now returns the verification code.

        return verificationCode;
    }

    /// <summary>
    /// Verifies email, if <paramref name="verificationCode"/> is correct.
    /// </summary>
    /// <param name="verificationCode"></param>
    /// <returns></returns>
    public async Task<IdentityResult> VerifyPhoneNumberAsync(string verificationCode)
    {
        CheckLoginStatus();

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, _userName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        user.ThrowIfParameterIsNull("IdentityInvalidUserName");

        await _lazyRedisCacheService.Value.ConnectAsync();

        var cacheKey = $"pvc_{user.UserName}";

        if (!await _lazyRedisCacheService.Value.KeyExistsAsync(cacheKey))
            throw new MilvaUserFriendlyException("ThereIsNoSavedVerificationCode");

        var verificationCodeInCache = await _lazyRedisCacheService.Value.GetAsync(cacheKey);

        if (verificationCode == verificationCodeInCache)
        {
            user.PhoneNumberConfirmed = true;

            return await _lazyUserManager.Value.UpdateAsync(user);
        }
        else throw new MilvaUserFriendlyException("WrongPhoneNumberVerificationCode");

    }

    /// <summary>
    /// Verifies <paramref name="emailVerificationDTO"/>.UserName's email, if <paramref name="emailVerificationDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="emailVerificationDTO"></param>
    /// <returns></returns>
    public async Task<IdentityResult> VerifyEmailAsync(EmailVerificationDTO emailVerificationDTO)
    {
        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, emailVerificationDTO.UserName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        user.ThrowIfParameterIsNull("InvalidVerificationToken");

        return await _lazyUserManager.Value.ConfirmEmailAsync(user, emailVerificationDTO.TokenString);
    }

    /// <summary>
    /// Changes <paramref name="emailChangeDTO"/>.UserName's email with <paramref name="emailChangeDTO"/>.NewEmail, if <paramref name="emailChangeDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="emailChangeDTO"></param>
    /// <returns></returns>
    public async Task<IdentityResult> ChangeEmailAsync(EmailChangeDTO emailChangeDTO)
    {
        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, emailChangeDTO.UserName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        user.ThrowIfParameterIsNull("InvalidVerificationToken");

        return await _lazyUserManager.Value.ChangeEmailAsync(user, emailChangeDTO.NewEmail, emailChangeDTO.TokenString);
    }

    /// <summary>
    /// Changes <paramref name="phoneNumberChangeDTO"/>.UserName's email 
    /// with <paramref name="phoneNumberChangeDTO"/>.NewPhoneNumber, if <paramref name="phoneNumberChangeDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="phoneNumberChangeDTO"></param>
    /// <returns></returns>
    public async Task<IdentityResult> ChangePhoneNumberAsync(PhoneNumberChangeDTO phoneNumberChangeDTO)
    {
        CheckLoginStatus();

        await VerifyPhoneNumberAsync(phoneNumberChangeDTO.VerificationCode, _userName);

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, _userName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        user.ThrowIfParameterIsNull(nameof(ResourceKey.InvalidVerificationToken));

        user.PhoneNumber = await _lazyMilvaEncryptionProvider.Value.EncryptAsync(phoneNumberChangeDTO.NewPhoneNumber);
        user.PhoneNumberConfirmed = true;

        var updateResult = await _lazyUserManager.Value.UpdateAsync(user);

        updateResult.ThrowErrorMessagesIfNotSuccess();

        await _lazyRedisCacheService.Value.PerformRedisActionAsync(async () =>
        {
            await _lazyRedisCacheService.Value.RemoveAsync(HelperExtensions.CreatePhoneNumberCacheKey(phoneNumberChangeDTO.NewPhoneNumber));

        }, nameof(ResourceKey.UpdateSuccessBut), _lazyMilvaLogger.Value);

        return updateResult;
    }

    /// <summary>
    /// Resets <paramref name="passwordResetDTO"/>.UserName's password with <paramref name="passwordResetDTO"/>.NewPassword, if <paramref name="passwordResetDTO"/>.TokenString is valid.
    /// </summary>
    /// <param name="passwordResetDTO"></param>
    /// <returns></returns>
    public async Task<IdentityResult> ResetPasswordAsync(PasswordResetDTO passwordResetDTO)
    {
        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, passwordResetDTO.UserName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        user.ThrowIfParameterIsNull("IdentityInvalidUserName");

        return await _lazyUserManager.Value.ResetPasswordAsync(user, passwordResetDTO.TokenString, passwordResetDTO.NewPassword);
    }

    /// <summary>
    /// Changes <paramref name="passwordChangeDTO"/>.UserName's <paramref name="passwordChangeDTO"/>.OldPassword with <paramref name="passwordChangeDTO"/>.NewPassword.
    /// </summary>
    /// <param name="passwordChangeDTO"></param>
    /// <returns></returns>
    public async Task<IdentityResult> ChangePasswordAsync(PasswordChangeDTO passwordChangeDTO)
    {
        CheckLoginStatus();

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, _userName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

        user.ThrowIfParameterIsNull("IdentityInvalidUserName");

        return await _lazyUserManager.Value.ChangePasswordAsync(user, passwordChangeDTO.OldPassword, passwordChangeDTO.NewPassword);
    }

    #endregion


    #region Admin

    /// <summary>
    /// Returns all users as paginated.
    /// </summary>
    /// <param name="paginationParams"></param>
    /// <returns></returns>
    public async Task<PaginationDTO<MilvaMongoTemplateUserDTO>> GetAllUsersAsync(PaginationParams paginationParams)
    {
        var appUserFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.AppUser, null);
        var isDeletedFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.IsDeleted, false);

        var (entities, pageCount, totalDataCount) = await _lazyUserRepository.Value.GetAsPaginatedAsync(paginationParams.PageIndex,
                                                                                              paginationParams.RequestedItemCount,
                                                                                              paginationParams.OrderByProps,
                                                                                              filterDefinition: Builders<MilvaMongoTemplateUser>.Filter.And(appUserFilter, isDeletedFilter));

        var allRoles = await _lazyRoleRepository.Value.GetAllAsync();

        return new PaginationDTO<MilvaMongoTemplateUserDTO>
        {
            DTOList = await entities.CheckListAsync(f => entities.Select(async user => new MilvaMongoTemplateUserDTO
            {
                Id = user.Id,
                UserName = user.UserName,
                Name = await _lazyMilvaEncryptionProvider.Value.DecryptAsync(user.Name),
                Surname = await _lazyMilvaEncryptionProvider.Value.DecryptAsync(user.Surname),
                Email = user.Email,
                PhoneNumber = await _lazyMilvaEncryptionProvider.Value.DecryptAsync(user.PhoneNumber),
                RoleNames = !user.Roles.IsNullOrEmpty()
                           ? allRoles.Where(r => user.Roles.Contains(r.Id.ToString())).Select(i => i.Name).ToList()
                           : null,
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
        var userIdFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.Id, userId);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userIdFilter.AddIsDeletedFilter());

        user.ThrowIfNullObject();

        var roles = (await _lazyRoleRepository.Value.GetAllAsync()).Where(r => user.Roles.Contains(r.Id.ToString()));

        return await user.CheckObjectAsync(async f => new MilvaMongoTemplateUserDTO
        {
            Id = user.Id,
            UserName = user.UserName,
            Name = await _lazyMilvaEncryptionProvider.Value.DecryptAsync(user.Name),
            Surname = await _lazyMilvaEncryptionProvider.Value.DecryptAsync(user.Surname),
            Email = user.Email,
            PhoneNumber = await _lazyMilvaEncryptionProvider.Value.DecryptAsync(user.PhoneNumber),
            RoleNames = !user.Roles.IsNullOrEmpty()
                            ? roles.Select(i => i.Name).ToList()
                            : null,
        });

    }

    /// <summary>
    /// Creates user according to <paramref name="userDTO"/> by admin.
    /// </summary>
    /// <param name="userDTO"></param>
    /// <returns></returns>
    public async Task<ObjectId> CreateUserAsync(MilvaMongoTemplateUserCreateDTO userDTO)
    {
        if (userDTO.Roles.IsNullOrEmpty())
            throw new MilvaUserFriendlyException("AtLeastSelectOneRole");

        MilvaMongoTemplateUser user = new()
        {
            UserName = userDTO.UserName,
            Email = userDTO.Email,
            Name = userDTO.Name,
            Surname = userDTO.Surname,
            PhoneNumber = userDTO.PhoneNumber
        };

        var createResult = await _lazyUserManager.Value.CreateAsync(user, userDTO.Password);

        if (createResult.Succeeded)
        {
            var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, user.UserName);

            user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

            var allRoles = await _lazyRoleRepository.Value.GetAllAsync();

            var roles = allRoles.Where(r => userDTO.Roles.Contains(r.Id));

            if (roles.IsNullOrEmpty())
                throw new MilvaUserFriendlyException("AtLeastSelectOneRole");

            user.Roles = roles.Select(r => r.Id.ToString()).ToList();

            var updateResult = await _lazyUserManager.Value.AddToRolesAsync(user, roles.Select(i => i.Name));

            ThrowErrorMessagesIfNotSuccess(updateResult);
        }
        else ThrowErrorMessagesIfNotSuccess(createResult);

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

        var toBeUpdatedUser = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userIdFilter.AddIsDeletedFilter());

        toBeUpdatedUser.ThrowIfNullObject();

        bool initializeUpdate = false;

        if (!string.IsNullOrEmpty(userDTO.NewName))
        {
            toBeUpdatedUser.Name = await _lazyMilvaEncryptionProvider.Value.EncryptAsync(userDTO.NewName);
            initializeUpdate = true;
        }

        if (!string.IsNullOrEmpty(userDTO.NewSurname))
        {
            toBeUpdatedUser.Surname = await _lazyMilvaEncryptionProvider.Value.EncryptAsync(userDTO.NewSurname);
            initializeUpdate = true;
        }

        if (!userDTO.NewRoles.IsNullOrEmpty())
        {
            var allRoles = await _lazyRoleRepository.Value.GetAllAsync();

            var newRoles = allRoles.Where(r => userDTO.NewRoles.Contains(r.Id)).Select(r => r.Name.ToString()).ToList();

            if (newRoles.IsNullOrEmpty())
                throw new MilvaUserFriendlyException("AtLeastSelectOneRole");

            var currentRoles = await _lazyUserManager.Value.GetRolesAsync(toBeUpdatedUser);

            var removeResult = await _lazyUserManager.Value.RemoveFromRolesAsync(toBeUpdatedUser, currentRoles);

            removeResult.ThrowErrorMessagesIfNotSuccess();

            var addResult = await _lazyUserManager.Value.AddToRolesAsync(toBeUpdatedUser, newRoles);

            addResult.ThrowErrorMessagesIfNotSuccess();
        }

        if (initializeUpdate)
        {
            toBeUpdatedUser.LastModificationDate = DateTime.Now;

            var updateResult = await _lazyUserManager.Value.UpdateAsync(toBeUpdatedUser);

            ThrowErrorMessagesIfNotSuccess(updateResult);
        }

        if (!string.IsNullOrEmpty(userDTO.NewPassword))
        {
            var token = await _lazyUserManager.Value.GeneratePasswordResetTokenAsync(toBeUpdatedUser);

            var resetResult = await _lazyUserManager.Value.ResetPasswordAsync(toBeUpdatedUser, token, userDTO.NewPassword);

            ThrowErrorMessagesIfNotSuccess(resetResult);
        }

        if (!string.IsNullOrEmpty(userDTO.NewEmail))
        {
            var token = await _lazyUserManager.Value.GenerateChangeEmailTokenAsync(toBeUpdatedUser, userDTO.NewPhoneNumber);

            var changeResult = await ChangeEmailAsync(new EmailChangeDTO
            {
                UserName = toBeUpdatedUser.UserName,
                NewEmail = userDTO.NewEmail,
                TokenString = token
            });

            ThrowErrorMessagesIfNotSuccess(changeResult);
        }

        if (!string.IsNullOrEmpty(userDTO.NewPhoneNumber))
        {
            var phoneNumber = await _lazyMilvaEncryptionProvider.Value.EncryptAsync(userDTO.NewPhoneNumber);

            var token = await _lazyUserManager.Value.GenerateChangePhoneNumberTokenAsync(toBeUpdatedUser, phoneNumber);

            var changeResult = await ChangePhoneNumberAsync(new PhoneNumberChangeDTO
            {
                UserName = toBeUpdatedUser.UserName,
                NewPhoneNumber = phoneNumber,
            });

            ThrowErrorMessagesIfNotSuccess(changeResult);
        }

    }

    /// <summary>
    /// Deletes user by <paramref name="userId"/> by admin.
    /// </summary>
    /// <param name="userId"></param>
    /// <returns></returns>
    public async Task DeleteUserAsync(ObjectId userId)
    {
        var userIdFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.Id, userId);

        var toBeDeletedUser = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userIdFilter.AddIsDeletedFilter());

        toBeDeletedUser.ThrowIfNullObject();

        if (toBeDeletedUser.AppUser != null)
            throw new MilvaUserFriendlyException("CannotDeleteAppUser");

        if (toBeDeletedUser.UserName == "admin")
            throw new MilvaUserFriendlyException("CannotDeleteDefaultAdminUser");

        var deleteResult = await _lazyUserManager.Value.DeleteAsync(toBeDeletedUser);

        ThrowErrorMessagesIfNotSuccess(deleteResult);
    }

    /// <summary>
    /// Returns all MilvaMongoTemplate app roles.
    /// </summary>
    /// <returns></returns>
    public async Task<List<MilvaMongoTemplateRoleDTO>> GetRolesAsync()
    {
        var roles = await _lazyRoleRepository.Value.GetAllAsync();

        return roles.CheckList(f => roles.Select(r => new MilvaMongoTemplateRoleDTO
        {
            Id = r.Id,
            Name = r.Name
        }));
    }

    #endregion


    #region Private Helper Methods

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
    public async Task<(MilvaMongoTemplateUser tUser, LoginResultDTO loginResult)> ValidateUser(LoginDTO loginDTO)
    {
        IdentityError GetLockedError(DateTime lockoutEnd)
        {
            var remainingLockoutEnd = lockoutEnd - DateTime.Now;

            var reminingLockoutEndString = remainingLockoutEnd.Hours > 0
                                            ? _localizer["Hours", remainingLockoutEnd.Hours]
                                            : remainingLockoutEnd.Minutes > 0
                                                 ? _localizer["Minutes", remainingLockoutEnd.Minutes]
                                                 : _localizer["Seconds", remainingLockoutEnd.Seconds];

            return new IdentityError { Code = "Locked", Description = _localizer["Locked", reminingLockoutEndString] };
        }

        int accessFailedCountLimit = 5;

        var user = new MilvaMongoTemplateUser();

        var loginResult = new LoginResultDTO { ErrorMessages = new List<IdentityError>() };

        if (loginDTO.UserName == null)
            throw new MilvaUserFriendlyException("PleaseEnterEmailOrUsername");

        //Kullanici adi veya email ile kullanici dogrulama
        #region User Validation

        var userNotFound = true;

        if (loginDTO.UserName != null)
        {
            var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, loginDTO.UserName);

            user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter());

            userNotFound = user == null;

            if (userNotFound)
            {
                loginResult.ErrorMessages.Add(new IdentityError { Code = "InvalidLogin", Description = _localizer["InvalidLogin"] });
                return (user, loginResult);
            }

            if (user.IsDeleted)
                throw new MilvaUserFriendlyException("AlreadyDeletedAccount");
        }

        if (userNotFound)
        {
            loginResult.ErrorMessages.Add(new IdentityError { Code = "InvalidLogin", Description = _localizer["InvalidLogin"] });

            return (user, loginResult);
        }

        var userLocked = await _lazyUserManager.Value.IsLockedOutAsync(user);

        if (userLocked && DateTime.Now > user.LockoutEnd.Value.DateTime)
        {
            //Locklanmış kullanıcının süresini sıfırlıyoruz
            await _lazyUserManager.Value.SetLockoutEndDateAsync(user, null);

            await _lazyUserManager.Value.ResetAccessFailedCountAsync(user);

            userLocked = false;
        }

        if (userLocked)
        {
            loginResult.ErrorMessages.Add(GetLockedError(user.LockoutEnd.Value.DateTime));
            return (user, loginResult);
        }

        var passIsTrue = await _lazyUserManager.Value.CheckPasswordAsync(user, loginDTO.Password);

        if (!passIsTrue)
        {
            _ = await _lazyUserManager.Value.AccessFailedAsync(user);

            if (await _lazyUserManager.Value.IsLockedOutAsync(user))
            {
                loginResult.ErrorMessages.Add(GetLockedError(user.LockoutEnd.Value.DateTime));
                return (user, loginResult);
            }

            var senstiveMessage = _localizer["InvalidLogin"];

            var lockWarningMessage = _localizer["LockWarning", accessFailedCountLimit - user.AccessFailedCount];

            loginResult.ErrorMessages.Add(new IdentityError { Code = "InvalidLogin", Description = lockWarningMessage });

            return (user, loginResult);
        }

        return (user, loginResult);

        #endregion
    }

    /// <summary>
    /// Roll is added according to user type and token is produced.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="isAppUser"></param>
    /// <returns></returns>
    public async Task<IToken> GenerateTokenWithRoleAsync(MilvaMongoTemplateUser user, bool isAppUser)
    {
        var roles = await _lazyUserManager.Value.GetRolesAsync(user);

        var newToken = GenerateToken(username: user.UserName, roles: roles, isAppUser);

        await _lazyUserManager.Value.RemoveAuthenticationTokenAsync(user, _loginProvider, _tokenName);

        IdentityResult identityResult = await _lazyUserManager.Value.SetAuthenticationTokenAsync(user: user,
                                                                                       loginProvider: _loginProvider,//Token nerede kullanılcak
                                                                                       tokenName: _tokenName,//Token tipi
                                                                                       tokenValue: newToken.AccessToken);

        if (!identityResult.Succeeded)
            throw new MilvaUserFriendlyException();

        return newToken;
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
        var uName = username ?? _userName;

        var userNameFilter = Builders<MilvaMongoTemplateUser>.Filter.Eq(a => a.UserName, uName);

        var user = await _lazyUserRepository.Value.GetFirstOrDefaultAsync(userNameFilter.AddIsDeletedFilter())
                                         ?? throw new MilvaUserFriendlyException(MilvaException.CannotFindEntity);

        if (string.IsNullOrEmpty(user?.Email))
            throw new MilvaUserFriendlyException("IdentityInvalidEmail");

        string token = "";

        switch (accountActivity)
        {
            case AccountActivity.EmailVerification:
                token = await _lazyUserManager.Value.GenerateEmailConfirmationTokenAsync(user);
                break;
            case AccountActivity.EmailChange:
                token = await _lazyUserManager.Value.GenerateChangeEmailTokenAsync(user, newInfo);
                break;
            case AccountActivity.PasswordReset:
                token = await _lazyUserManager.Value.GeneratePasswordResetTokenAsync(user);
                break;
            case AccountActivity.PhoneNumberChange:
                token = await _lazyUserManager.Value.GenerateChangePhoneNumberTokenAsync(user, await _lazyMilvaEncryptionProvider.Value.EncryptAsync(newInfo));
                break;
        }

        var confirmationUrl = $"{GlobalConstant.ApplicationSiteUrl}/{urlPath}?userName={username ?? _userName}&token={token}";

        var htmlContent = await File.ReadAllTextAsync(Path.Combine(GlobalConstant.RootPath, "StaticFiles", "HTML", "mail_content.html"));

        foreach (var localizedMailBodyContent in localizedMailBodyContents)
            htmlContent = htmlContent.Replace(localizedMailBodyContent.Key, localizedMailBodyContent.Value);

        htmlContent = htmlContent.Replace("~BodyButtonLink", confirmationUrl);

        await _lazyMilvaMailSender.Value.MilvaSendMailAsync(user.Email, localizedMailBodyContents["~MailTitle"], htmlContent, true);
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

    #endregion
}
