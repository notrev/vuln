using Microsoft.AspNetCore.Identity;
using Vuln.Enums;
using Vuln.Models;

namespace Vuln.Data
{
    public class UserToSeed
    {
        required public ApplicationUser User { get; set; }
        required public List<UserRole> Roles { get; set; }
        required public string Password { get; set; }
    }

    public class DbSeeder
    {
        public static async Task SeedData(IApplicationBuilder app)
        {
            using IServiceScope scope = app.ApplicationServices.CreateScope();

            ILogger<DbSeeder> logger = scope.ServiceProvider.GetRequiredService<ILogger<DbSeeder>>();

            try
            {
                UserManager<ApplicationUser>? userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
                RoleManager<IdentityRole>? roleManager = scope.ServiceProvider.GetService<RoleManager<IdentityRole>>();

                // Seed roles
                logger.LogInformation("Seeding UserRoles to database");
                foreach (UserRole role in Enum.GetValues(typeof(UserRole)))
                {
                    if (roleManager != null && (await roleManager.RoleExistsAsync(role.ToString())) == false)
                    {
                        logger.LogInformation($"{role} role is being created");
                        var roleResult = await roleManager.CreateAsync(new IdentityRole(role.ToString()));

                        if (roleResult.Succeeded == false)
                        {
                            var roleErros = roleResult.Errors.Select(e => e.Description);
                            logger.LogError($"Failed to create {role} role. Errors : {string.Join(",", roleErros)}");

                            return;
                        }
                        logger.LogInformation($"{role} role is created");
                    }
                }

                // Seed users
                List<UserToSeed> usersToSeed =
                [
                    new UserToSeed {
                        User = new ApplicationUser {
                            UserName = "publisher",
                            Email = "publisher@vuln.sec",
                            EmailConfirmed = true,
                            SecurityStamp = Guid.NewGuid().ToString()
                        },
                        Roles = [UserRole.Writer],
                        Password = "th1s!1s@N0t#Th3$Password%You&Are*Looking(For)",
                    },
                    new UserToSeed {
                        User = new ApplicationUser {
                            UserName = "reader",
                            Email = "reader@vuln.sec",
                            EmailConfirmed = true,
                            SecurityStamp = Guid.NewGuid().ToString()
                        },
                        Roles = [UserRole.Reader],
                        Password = "1!W0nt@Tell$You"
                    },
                    new UserToSeed {
                        User = new ApplicationUser {
                            UserName = "radiant",
                            Email = "radiant@vuln.sec",
                            EmailConfirmed = true,
                            SecurityStamp = Guid.NewGuid().ToString()
                        },
                        Roles = [UserRole.Writer, UserRole.Reader],
                        Password = "l1fe!B3f0r3@D34th#Journey%Before&Destination*",
                    }
                ];

                // Check if any users exist to prevent duplicate seeding
                logger.LogInformation("Seeding Users to database");
                if (userManager?.Users.Any() == false)
                {
                    foreach (UserToSeed userToSeed in usersToSeed)
                    {
                        var createUserResult = await userManager.CreateAsync(user: userToSeed.User, password: userToSeed.Password);

                        // Validate user creation
                        if (createUserResult.Succeeded == false)
                        {
                            var errors = createUserResult.Errors.Select(e => e.Description);
                            logger.LogError($"Failed to create user {userToSeed.User.UserName}. Errors: {string.Join(", ", errors)}");
                            return;
                        }

                        foreach (UserRole role in userToSeed.Roles)
                        {
                            var addRoleResult = await userManager.AddToRoleAsync(user: userToSeed.User, role: role.ToString());

                            if (addRoleResult.Succeeded == false)
                            {
                                var errors = addRoleResult.Errors.Select(e => e.Description);
                                logger.LogError($"Failed to add {role} role to user {userToSeed.User.UserName}. Errors: {string.Join(", ", errors)}");
                            }
                        }

                        logger.LogInformation($"{userToSeed.User.UserName} user is created");
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogCritical(ex.Message);
            }
        }
    }
}