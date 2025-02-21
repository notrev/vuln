using System.Drawing;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Identity;
using Vuln.Enums;
using Vuln.Models;
using Vuln.Services;

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
        public static async Task SeedRolesAndUsers(IApplicationBuilder app, bool shouldSeedUsers = false)
        {
            using IServiceScope scope = app.ApplicationServices.CreateScope();

            ILogger<DbSeeder> logger = scope.ServiceProvider.GetRequiredService<ILogger<DbSeeder>>();

            try
            {
                RoleManager<IdentityRole>? roleManager = scope.ServiceProvider.GetService<RoleManager<IdentityRole>>() ?? 
                    throw new Exception("Can not seed user roles: RoleManager is not available");

                await SeedRoles(roleManager, logger);

                if (shouldSeedUsers)
                {
                    UserManager<ApplicationUser>? userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>() ??
                        throw new Exception("Can not seed users: RoleManager is not available");
                    await SeedUsers(userManager, logger);                
                }
            }
            catch (Exception ex)
            {
                logger.LogCritical(ex.Message);
            }

        }
        
        private static async Task SeedRoles(RoleManager<IdentityRole> roleManager, ILogger<DbSeeder> logger)
        {
            // Seed roles
            logger.LogInformation("Seeding UserRoles to database");
            foreach (UserRole role in Enum.GetValues(typeof(UserRole)))
            {
                if (await roleManager.RoleExistsAsync(role.ToString()) == false)
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
        }

        private static async Task SeedUsers(UserManager<ApplicationUser> userManager, ILogger<DbSeeder> logger)
        {
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
            if (userManager.Users.Any() == true)
            {
                return;
            }

            logger.LogInformation("Seeding Users to database");
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

        public static async Task SeedVulnerabilities(IApplicationBuilder app)
        {
            using IServiceScope scope = app.ApplicationServices.CreateScope();
            ILogger<DbSeeder> logger = scope.ServiceProvider.GetRequiredService<ILogger<DbSeeder>>();

            try
            {
                var vulnerabilityService = scope.ServiceProvider.GetRequiredService<VulnerabilityService>();

                if (vulnerabilityService.GetVulnerabilities().Result.Count > 0)
                {
                    return;
                }

                logger.LogInformation("Seeding Vulnerabilities to database");

                List<Vulnerability> vulnerabilities =
                [
                    new Vulnerability
                    {
                        Id = "vulnerability--c7cab3fb-0822-43a5-b1ba-c9bab34361a2",
                        SpecVersion = "2.1",
                        Created = DateTime.Parse("2015-05-15T09:12:16.432Z"),
                        Modified = DateTime.Parse("2015-05-15T09:12:16.432Z"),
                        Name = "CVE-2012-0158",
                        Description = "Weaponized Microsoft Word document used by admin@338",
                        ExternalReferences = 
                        [
                            new ExternalReference
                            {
                                SourceName = "cve",
                                ExternalId = "CVE-2012-0158"
                            }
                        ]
                    },
                    new Vulnerability
                    {
                        Id = "vulnerability--6a2eab9c-9789-4437-812b-d74323fa3bca",
                        SpecVersion = "2.1",
                        Created = DateTime.Parse("2015-05-15T09:12:16.432Z"),
                        Modified = DateTime.Parse("2015-05-15T09:12:16.432Z"),
                        Name = "CVE-2009-4324",
                        Description = "Adobe acrobat PDF's used by admin@338",
                        ExternalReferences =
                        [
                            new ExternalReference
                            {
                                SourceName = "cve",
                                ExternalId = "CVE-2009-4324"
                            }
                            
                        ]
                    },
                    new Vulnerability
                    {
                        Id = "vulnerability--2b7f00d8-b133-4a92-9118-46ce5f8b2531",
                        SpecVersion = "2.1",
                        Created = DateTime.Parse("2015-05-15T09:12:16.432Z"),
                        Modified = DateTime.Parse("2015-05-15T09:12:16.432Z"),
                        Name = "CVE-2013-0422",
                        Description = "Java 7 vulnerability exploited by th3bug",
                        ExternalReferences =
                        [
                            new ExternalReference
                            {
                                SourceName = "cve",
                                ExternalId = "CVE-2013-0422"
                            }
                        ]
                    },
                ];

                foreach (Vulnerability vulnerability in vulnerabilities)
                {
                    await vulnerabilityService.AddVulnerability(vulnerability);
                }
            }
            catch (Exception ex)
            {
                logger.LogCritical(ex.Message);
            }
        }
    }
}