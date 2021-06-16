using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MilvaMongoTemplate.Entity.Collections;
using System;
using System.Collections.Generic;

namespace MilvaMongoTemplate.Data.Utils
{
    /// <summary>
    /// MilvaMongoTemplate user manager.
    /// </summary>
    public class MilvaMongoTemplateUserManager : UserManager<MilvaMongoTemplateUser>
    {
        /// <summary>
        /// Initializes new instance of <see cref="MilvaMongoTemplateUserManager"/>.
        /// </summary>
        /// <param name="store"></param>
        /// <param name="optionsAccessor"></param>
        /// <param name="passwordHasher"></param>
        /// <param name="userValidators"></param>
        /// <param name="passwordValidators"></param>
        /// <param name="keyNormalizer"></param>
        /// <param name="errors"></param>
        /// <param name="services"></param>
        /// <param name="logger"></param>
        public MilvaMongoTemplateUserManager(IUserStore<MilvaMongoTemplateUser> store,
                                             IOptions<IdentityOptions> optionsAccessor,
                                             IPasswordHasher<MilvaMongoTemplateUser> passwordHasher,
                                             IEnumerable<IUserValidator<MilvaMongoTemplateUser>> userValidators,
                                             IEnumerable<IPasswordValidator<MilvaMongoTemplateUser>> passwordValidators,
                                             ILookupNormalizer keyNormalizer,
                                             IdentityErrorDescriber errors,
                                             IServiceProvider services,
                                             ILogger<UserManager<MilvaMongoTemplateUser>> logger) : base(store,
                                                                                                         optionsAccessor,
                                                                                                         passwordHasher,
                                                                                                         userValidators,
                                                                                                         passwordValidators,
                                                                                                         keyNormalizer,
                                                                                                         errors,
                                                                                                         services,
                                                                                                         logger)
        { }
    }
}
