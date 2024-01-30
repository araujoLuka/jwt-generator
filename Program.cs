using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

internal class Program
{
    private static int Main(string[] args)
    {
        void PrintHelp()
        {
            // usage ./jwtGen <username> <password> <secret> [expiration]
            Console.WriteLine(
                "JWT Generator\n" +
                "Usage:\n" +
                "  ./jwtGen [-h | --help] [-e | --exp <expiration>] [-r | --role <role>]\n" +
                "           [-s | --script]  [<username>] [<password>] [<secret>]\n" +
                "\n" +
                "Optional Arguments:\n" +
                "  username    Username to use in the JWT\n" +
                "              - if not specified, request it from stdin\n" +
                "  password    Password to use in the JWT\n" +
                "              - if not specified, request it from stdin\n" +
                "  secret      Secret key with at least 32 characters\n" +
                "              - if not specified, generate a random one\n" +
                "\n" +
                "Options:\n" +
                "  -h, --help  Show this screen.\n" +
                "  -e, --exp   Expiration time in minutes (default: 43200 = 30 days)\n" +
                "              0 = default expiration time\n" +
                "  -r, --role  Role to use in the JWT (default: admin)\n" +
                "  -s, --script  Do not print any help or interactive text\n" +
                "\n" +
                "Example:\n" +
                "  ./jwtGen -e 60 -r admin admin password12345678901234567890123456789012\n" +
                "\n" +
                "Output:\n" +
                "  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsIm5iZiI6MTU1NjI5NjQwMCwiZXhwIjoxNTU2MzAwMDAwfQ." +
                "\n" +
                "Tips:\n" +
                " - Use https://jwt.io/ to decode the JWT\n" +
                " - Try not to use an expiration time of 0\n"
            );
        }

        const long DEFAULT_EXPIRATION = 43200;

        string username = "";
        string password = "";
        string secret = "";
        long expiration = DEFAULT_EXPIRATION;
        string role = "admin";
        bool script = false;
        string? line = null;

        if (args.Length > 6)
        {
            PrintHelp();
            return -1;
        }

        // Parse options
        for (int i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("-") && !args[i].StartsWith("--"))
                continue;

            switch (args[i])
            {
                case "-h":
                case "--help":
                    PrintHelp();
                    return 0;
                case "-e":
                case "--exp":
                    expiration = int.Parse(args[i + 1]);
                    if (expiration <= 0) expiration = DEFAULT_EXPIRATION;
                    args[i] = "";
                    args[i + 1] = "";
                    break;
                case "-r":
                case "--role":
                    role = args[i + 1];
                    args[i] = "";
                    args[i + 1] = "";
                    break;
                case "-s":
                case "--script":
                    script = true;
                    args[i] = "";
                    break;
            }
        }

        args = args.Where(x => !string.IsNullOrEmpty(x)).ToArray();

        // Print an apresentative message
        const string message =
            "JWT Generator\n" +
            "- - - - - -\n" +
            "This program will generate a JWT token with the given username and password.\n";
        if (!script)
            Console.WriteLine(message);

        if (args.Length < 2)
        {
            if (!script)
            {
                Console.WriteLine("Missing arguments");
                Console.WriteLine("Getting username and password from stdin");
            }

            if (!script)
                Console.Write("Username: ");
            else
                Console.Write("USER=");
            line = Console.ReadLine();
            if (line == null)
            {
                Console.WriteLine("Error: Username cannot be empty");
                Console.WriteLine("Try ./jwtGen -h for help");
                return 1;
            }
            username = line;

            if (!script)
                Console.Write("Password: ");
            else
                Console.Write("PASS=");
            line = Console.ReadLine();
            if (line == null)
            {
                Console.WriteLine("Error: Password cannot be empty");
                Console.WriteLine("Try ./jwtGen -h for help");
                return 1;
            }
            password = line;
        }
        else
        {
            username = args[0];
            password = args[1];
            if (!script)
            {
                Console.WriteLine("Using username: " + username);
                Console.WriteLine("Using password: " + password);
            }
            else
            {
                Console.WriteLine("USER:\n\t" + username);
                Console.WriteLine("PASS:\n\t" + password);
            }
            args[0] = "";
            args[1] = "";
            args = args.Where(x => !string.IsNullOrEmpty(x)).ToArray();
        }

        if (!script)
        {
            Console.WriteLine("Using role: " + role);
            Console.WriteLine("Using expiration: " + expiration);
            Console.WriteLine("Would like to change any of these? (y/n)");
            line = Console.ReadLine();
            if (line != null && line.ToLower() == "y")
            {
                Console.WriteLine("Changing... Leave empty to keep the same");
                Console.Write("Role (default: admin): ");
                line = Console.ReadLine();
                if (line != null) role = line;

                Console.Write("Expiration (default: " + DEFAULT_EXPIRATION + "): ");
                line = Console.ReadLine();
                if (line != null)
                {
                    if (!long.TryParse(line, out expiration))
                    {
                        Console.WriteLine("Error: Invalid expiration time");
                        Console.WriteLine("Using default: " + DEFAULT_EXPIRATION);
                    }
                }
            }
        }

        if (args.Length > 0)
        {
            secret = args[0];
            if (secret.Length < 32)
            {
                Console.WriteLine("Secret must be at least 32 characters long");
                return 2;
            }
        }
        else
        {
            if (!script)
            {
                Console.WriteLine("Do you want to use a custom secret? (y/n)");
                line = Console.ReadLine();
                if (line != null && line.ToLower() == "y")
                {
                    Console.Write("Secret: ");
                    line = Console.ReadLine();
                    if (line == null)
                    {
                        Console.WriteLine("Error: Secret cannot be empty");
                        Console.WriteLine("Using a random one");
                        secret = Guid.NewGuid().ToString();
                    }
                    else
                    {
                        secret = line;
                        if (secret.Length < 32)
                        {
                            Console.WriteLine("Secret must be at least 32 characters long");
                            return 2;
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Using a random secret");
                    secret = Guid.NewGuid().ToString();
                }
            }
            else
                secret = Guid.NewGuid().ToString();
        }

        if (!script)
            Console.WriteLine("Using secret: " + secret);
        else
            Console.WriteLine("SECRET:\n\t" + secret);

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(secret);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, "admin")
            }),
            Expires = DateTime.UtcNow.AddMinutes(expiration),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        DateTime? expirationTime = tokenDescriptor.Expires;
        expirationTime = expirationTime?.ToLocalTime();

        if (!script)
        {
            Console.WriteLine("\n\nYour JWT token is:\n" + tokenString);
            Console.WriteLine("It will expire at: " + expirationTime);
        }
        else
        {
            Console.WriteLine("EXPIRATION:\n\t" + expirationTime);
            Console.WriteLine("JWT:\n\t" + tokenString);
        }
        return 0;
    }
}
