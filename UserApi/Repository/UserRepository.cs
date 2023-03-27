using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UserApi.Interfaces;
using UserApi.Models;

namespace UserApi.Repository
{
    public class UserRepository : IUser
    {
        private readonly NodeContext NodeDbContext;
        private readonly IConfiguration Configuration;

        public UserRepository(NodeContext nodeDbContext, IConfiguration iConfiguration)
        {
            this.NodeDbContext = nodeDbContext;
            this.Configuration = iConfiguration;

        }
        public User GetUser(string username)
        {
            var user = this.NodeDbContext.Users.FirstOrDefault(o => username.Equals(o.Username) || username.Equals(o.Email));
            return user;
        }

        public User GetUser(int id)
        {
            var user = this.NodeDbContext.Users.FirstOrDefault(o => id == o.UserId);
            return user;
        }

        public List<User> GetUsers()
        {
            var users = this.NodeDbContext.Users.ToList();
            return users;
        }

        public User RegisterUser(User user)
        {
            if (user != null)
            {
                this.NodeDbContext.Users.Add(user);
                this.NodeDbContext.SaveChanges();
                user = NodeDbContext.Users.FirstOrDefault(o => user.Username.Equals(o.Username) || user.Email.Equals(o.Email));
                return user;
            }
            return null;
        }
    }
}