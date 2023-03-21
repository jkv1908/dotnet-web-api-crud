using System.Text.Json.Serialization;

namespace UserApi.Models;

public partial class User
{
    public int UserId { get; set; }

    public string? Username { get; set; }

    public string? Email { get; set; }

    [JsonIgnore]
    public string? Password { get; set; }
}
