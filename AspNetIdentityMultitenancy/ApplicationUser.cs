namespace QuickAndEasyAspNetIdentityMultitenanc.Identity
{
    using System;

    using Microsoft.AspNet.Identity.EntityFramework;

    public class ApplicationUser : ApplicationUser<string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
    {
        public ApplicationUser()
        {
            Id = Guid.NewGuid().ToString();
        }

        public ApplicationUser(string userName)
            : this()
        {
            UserName = userName;
        }
    }

    public class ApplicationUser<TKey, TLogin, TRole, TClaim> : IdentityUser<TKey, TLogin, TRole, TClaim>
        where TLogin : IdentityUserLogin<TKey> 
        where TRole : IdentityUserRole<TKey> 
        where TClaim : IdentityUserClaim<TKey>
    {
        public ApplicationUser()
            : base()
        {
        }

        public int TenantId { get; set; }

    }

    
}