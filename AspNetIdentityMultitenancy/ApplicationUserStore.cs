namespace QuickAndEasyAspNetIdentityMultitenancy.Identity
{
    using System;
    using System.Data.Entity;
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity.EntityFramework;

    public class ApplicationUserStore<TUser> :
        ApplicationUserStore<TUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
        where TUser : ApplicationUser
    {
        public ApplicationUserStore()
            : this(new IdentityDbContext())
        {
            DisposeContext = true;
        }

        public ApplicationUserStore(DbContext context)
            : base(context)
        {
        }
    }

    public class ApplicationUserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> : 
        UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim>
        where TKey : IEquatable<TKey>
        where TUser : ApplicationUser<TKey, TUserLogin, TUserRole, TUserClaim>
        where TRole : IdentityRole<TKey, TUserRole>
        where TUserLogin : IdentityUserLogin<TKey>, new()
        where TUserRole : IdentityUserRole<TKey>, new()
        where TUserClaim : IdentityUserClaim<TKey>, new()
    {
        public ApplicationUserStore(DbContext context)
            : base(context)
        {
        }

        public int TenantId { get; set; }

        public override Task CreateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.TenantId = this.TenantId;

            return base.CreateAsync(user);
        }

        public override Task<TUser> FindByEmailAsync(string email)
        {
            return this.GetUserAggregateAsync(u => u.Email.ToUpper() == email.ToUpper() && u.TenantId == this.TenantId);
        }

        public override Task<TUser> FindByNameAsync(string userName)
        {
            return this.GetUserAggregateAsync(u => u.UserName.ToUpper() == userName.ToUpper() && u.TenantId == this.TenantId);
        }
    }
}