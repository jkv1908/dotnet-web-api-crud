using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UserApi.Models;

namespace UserApi.Interfaces
{
    public interface IUser
    {
        public User GetUser(string userName);
        public List<User> GetUsers();
        public User RegisterUser(User user);
        public User GetUser(int id);
    }
}