using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UserApi.Models;
using Microsoft.AspNetCore.Mvc;
using BCrypt.Net;
using Microsoft.AspNetCore.Http.HttpResults;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Newtonsoft.Json;

namespace UserApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class UserController : ControllerBase
    {

        private readonly NodeContext NodeDbContext;
        private readonly IConfiguration Configuration;

        public UserController(NodeContext nodeContext, IConfiguration configuration)
        {
            this.NodeDbContext = nodeContext;
            this.Configuration = configuration;
        }

        [HttpPost(Name = "Register")]
        public IActionResult Register([FromBody] Register register)
        {
            try
            {
                if (string.IsNullOrEmpty(register.username) || string.IsNullOrEmpty(register.password) || string.IsNullOrEmpty(register.email))
                {
                    return BadRequest("Please provide all the inputs");
                }
                var User = NodeDbContext.Users.FirstOrDefault(o => register.username.Equals(o.Username) || register.email.Equals(o.Email));
                if (User == null)
                {
                    User = new User();
                    User.Username = register.username;
                    User.Email = register.email;
                    var password = BCrypt.Net.BCrypt.HashPassword(register.password, 10);
                    User.Password = password;
                    this.NodeDbContext.Users.Add(User);
                    this.NodeDbContext.SaveChanges();
                    User = NodeDbContext.Users.FirstOrDefault(o => register.username.Equals(o.Username) || register.email.Equals(o.Email));
                    if (User != null)
                    {
                        User.Password = "";
                        return Ok(User);
                    }
                    else
                    {
                        return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                    }

                }
                else
                {
                    return new StatusCodeResult(StatusCodes.Status409Conflict);
                }
            }
            catch (System.Exception ex)
            {
                System.Console.WriteLine(ex);
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);


            }

        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] Login login)
        {
            try
            {
                if (string.IsNullOrEmpty(login.Username) || string.IsNullOrEmpty(login.Password))
                {
                    return BadRequest("Please provide all the inputs");
                }
                var User = NodeDbContext.Users.FirstOrDefault(o => login.Username.Equals(o.Username) || login.Username.Equals(o.Email));
                if (User != null)
                {
                    var match = BCrypt.Net.BCrypt.Verify(login.Password, User.Password);
                    if (match)
                    {
                        string jwtToken = GenerateJwtToken(User.UserId);
                        return Ok(new { Token = jwtToken, });
                    }
                    else
                    {
                        return Unauthorized();
                    }


                }
                else
                {
                    return Unauthorized();
                }
            }
            catch (System.Exception ex)
            {
                System.Console.WriteLine(ex);
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);


            }

        }
        [HttpGet("{username}")]
        public IActionResult Get(string username)
        {
            try
            {
                var re = Request;
                var headers = re.Headers;
                var token = headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
                Boolean validated = validateJwtToken(token);
                if (validated)
                {
                    var user = this.NodeDbContext.Users.FirstOrDefault(o => username.Equals(o.Username) || username.Equals(o.Email));
                    if (user != null)
                    {
                        return Ok(user);
                    }
                    else
                    {
                        return NotFound("User not found");
                    }
                }
                else
                {
                    return Unauthorized();
                }
            }
            catch (Exception ex)
            {
                System.Console.WriteLine(ex.ToString());

                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }
        [HttpGet(Name = "GetUserDetails")]
        public IActionResult Get()
        {
            try
            {
                var re = Request;
                var headers = re.Headers;
                var token = headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

                Boolean validated = validateJwtToken(token);
                if (validated)
                {
                    var userDetails = headers["user"].FirstOrDefault()?.Split(" ").Last();
                    var user = JsonConvert.DeserializeObject<User>(userDetails);
                    //var user = this.NodeDbContext.Users.FirstOrDefault(o => username.Equals(o.Username) || username.Equals(o.Email));

                    if (user != null)
                    {
                        return Ok(user);
                    }
                    else
                    {
                        return NotFound("User not found");
                    }
                }
                else
                {
                    return Unauthorized();
                }
            }
            catch (Exception ex)
            {
                System.Console.WriteLine(ex.ToString());

                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }

        [HttpGet("list")]
        public IActionResult GetList()
        {
            var users = this.NodeDbContext.Users.ToList();
            return Ok(users);
        }

        private string GenerateJwtToken(int userName)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(Configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", userName.ToString()) }),
                Expires = DateTime.UtcNow.AddMinutes(10),
                Issuer = Configuration["Jwt:Issuer"],
                Audience = Configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private Boolean validateJwtToken(string token)
        {
            Boolean isAuthorized = false;
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(Configuration["Jwt:Key"]);
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero,
                    ValidIssuer = Configuration["Jwt:Issuer"],
                    ValidAudience = Configuration["Jwt:Audience"],
                }, out SecurityToken validatedToken);
                var jwtToken = (JwtSecurityToken)validatedToken;
                var UserId = jwtToken.Claims.First(x => x.Type == "id").Value;
                if (UserId != null)
                {
                    int userIdInt = Int32.Parse(UserId);
                    var user = this.NodeDbContext.Users.FirstOrDefault(o => userIdInt == o.UserId);
                    if (user != null)
                    {
                        var request = Request;
                        request.Headers.Add("user", JsonConvert.SerializeObject(user));
                        isAuthorized = true;
                    }

                }
                //System.Console.WriteLine($"jwtToken - {jwtToken} - accountId -{UserId}");

            }
            catch (System.Exception ex)
            {
                System.Console.WriteLine(ex.ToString());

            }
            return isAuthorized;
        }

    }
}