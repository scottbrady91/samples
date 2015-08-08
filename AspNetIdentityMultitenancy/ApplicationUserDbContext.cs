namespace QuickAndEasyAspNetIdentityMultitenanc.Identity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Common;
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    using System.Data.Entity.Infrastructure.Annotations;
    using System.Data.Entity.Validation;
    using System.Linq;

    using Microsoft.AspNet.Identity.EntityFramework;

    public class ApplicationUserDbContext :
        ApplicationUserDbContext<ApplicationUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
    {
        public ApplicationUserDbContext()
            : this("DefaultConnection")
        {
        }

        public ApplicationUserDbContext(string nameOrConnectionString)
            : base(nameOrConnectionString)
        {
        }

        public ApplicationUserDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection)
            : base(existingConnection, model, contextOwnsConnection)
        {
        }

        public ApplicationUserDbContext(DbCompiledModel model)
            : base(model)
        {
        }

        public ApplicationUserDbContext(DbConnection existingConnection, bool contextOwnsConnection)
            : base(existingConnection, contextOwnsConnection)
        {
        }

        public ApplicationUserDbContext(string nameOrConnectionString, DbCompiledModel model)
            : base(nameOrConnectionString, model)
        {
        }
    }

    public class ApplicationUserDbContext<TUser> :
        ApplicationUserDbContext<TUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
        where TUser : ApplicationUser
    {
        public ApplicationUserDbContext()
            : this("DefaultConnection")
        {
        }

        public ApplicationUserDbContext(string nameOrConnectionString)
            : base(nameOrConnectionString)
        {
        }

        public ApplicationUserDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection)
            : base(existingConnection, model, contextOwnsConnection)
        {
        }

        public ApplicationUserDbContext(DbCompiledModel model)
            : base(model)
        {
        }

        public ApplicationUserDbContext(DbConnection existingConnection, bool contextOwnsConnection)
            : base(existingConnection, contextOwnsConnection)
        {
        }

        public ApplicationUserDbContext(string nameOrConnectionString, DbCompiledModel model)
            : base(nameOrConnectionString, model)
        {
        }
    }

    public class ApplicationUserDbContext<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> :
        IdentityDbContext<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim>
        where TUser : ApplicationUser<TKey, TUserLogin, TUserRole, TUserClaim>
        where TRole : IdentityRole<TKey, TUserRole>
        where TUserLogin : IdentityUserLogin<TKey>
        where TUserRole : IdentityUserRole<TKey>
        where TUserClaim : IdentityUserClaim<TKey>
    {
        public ApplicationUserDbContext()
            : this("DefaultConnection")
        {
        }

        public ApplicationUserDbContext(string nameOrConnectionString)
            : base(nameOrConnectionString)
        {
        }

        public ApplicationUserDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection)
            : base(existingConnection, model, contextOwnsConnection)
        {
        }

        public ApplicationUserDbContext(DbCompiledModel model)
            : base(model)
        {
        }

        public ApplicationUserDbContext(DbConnection existingConnection, bool contextOwnsConnection)
            : base(existingConnection, contextOwnsConnection)
        {
        }

        public ApplicationUserDbContext(string nameOrConnectionString, DbCompiledModel model)
            : base(nameOrConnectionString, model)
        {
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            var user = modelBuilder.Entity<TUser>();

            user.Property(u => u.UserName)
                .IsRequired()
                .HasMaxLength(256)
                .HasColumnAnnotation("Index", new IndexAnnotation(new IndexAttribute("UserNameIndex") { IsUnique = true, Order = 1}));

            user.Property(u => u.TenantId)
                .IsRequired()
                .HasColumnAnnotation("Index", new IndexAnnotation(new IndexAttribute("UserNameIndex") { IsUnique = true, Order = 2 }));
        }

        protected override DbEntityValidationResult ValidateEntity(DbEntityEntry entityEntry, IDictionary<object, object> items)
        {
            if (entityEntry != null && entityEntry.State == EntityState.Added)
            {
                var errors = new List<DbValidationError>();
                var user = entityEntry.Entity as TUser;

                if (user != null)
                {
                    if (this.Users.Any(u => string.Equals(u.UserName, user.UserName) && u.TenantId == user.TenantId))
                    {
                        errors.Add(
                            new DbValidationError("User", string.Format("Username {0} is already taken for AppId {1}", user.UserName, user.TenantId)));
                    }

                    if (this.RequireUniqueEmail && this.Users.Any(u => string.Equals(u.Email, user.Email) && u.TenantId == user.TenantId))
                    {
                        errors.Add(
                            new DbValidationError(
                                "User", 
                                string.Format("Email Address {0} is already taken for AppId {1}", user.UserName, user.TenantId)));
                    }
                }
                else
                {
                    var role = entityEntry.Entity as TRole;

                    if (role != null && this.Roles.Any(r => string.Equals(r.Name, role.Name)))
                    {
                        errors.Add(new DbValidationError("Role", string.Format("Role {0} already exists", role.Name)));
                    }
                }

                if (errors.Any())
                {
                    return new DbEntityValidationResult(entityEntry, errors);
                }
            }

            return new DbEntityValidationResult(entityEntry, new List<DbValidationError>());
        }
    }
}