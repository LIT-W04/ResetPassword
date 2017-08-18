using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthDemo.Data
{
    public class UserAuthDb
    {
        private string _connectionString;

        public UserAuthDb(string connectionString)
        {
            _connectionString = connectionString;
        }

        public void AddUser(User user, string password)
        {
            string salt = PasswordHelper.GenerateSalt();
            string passwordHash = PasswordHelper.HashPassword(password, salt);
            user.PasswordSalt = salt;
            user.PasswordHash = passwordHash;

            using (SqlConnection connection = new SqlConnection(_connectionString))
            using (SqlCommand command = connection.CreateCommand())
            {
                command.CommandText = "INSERT INTO Users (FirstName, LastName, Email, PasswordHash, Salt)" +
                                      " VALUES (@firstName, @lastName, @email, @hash, @salt)";
                command.Parameters.AddWithValue("@firstName", user.FirstName);
                command.Parameters.AddWithValue("@lastName", user.LastName);
                command.Parameters.AddWithValue("@email", user.Email);
                command.Parameters.AddWithValue("@hash", user.PasswordHash);
                command.Parameters.AddWithValue("@salt", user.PasswordSalt);
                connection.Open();
                command.ExecuteNonQuery();
            }
        }

        public User Login(string email, string password)
        {
            User user = GetByEmail(email);
            if (user == null)
            {
                return null;
            }
            bool isCorrectPassword = PasswordHelper.PasswordMatch(password, user.PasswordSalt, user.PasswordHash);
            if (!isCorrectPassword)
            {
                return null;
            }

            return user;
        }

        public User GetByEmail(string email)
        {
            using (SqlConnection connection = new SqlConnection(_connectionString))
            using (SqlCommand command = connection.CreateCommand())
            {
                command.CommandText = "SELECT * FROM Users WHERE Email = @email";
                command.Parameters.AddWithValue("@email", email);
                connection.Open();
                SqlDataReader reader = command.ExecuteReader();
                if (!reader.Read())
                {
                    return null;
                }

                return GetUserFromReader(reader);
            }
        }

        private User GetUserFromReader(SqlDataReader reader)
        {
            User user = new User
            {
                Id = (int)reader["Id"],
                FirstName = (string)reader["FirstName"],
                LastName = (string)reader["LastName"],
                Email = (string)reader["Email"],
                PasswordHash = (string)reader["PasswordHash"],
                PasswordSalt = (string)reader["Salt"]
            };
            return user;
        }

        public UserGuid AddForgottenPassword(string email)
        {
            Guid guid = Guid.NewGuid();

            User user = GetByEmail(email);
            if (user == null)
            {
                return null;
            }

            using (var connection = new SqlConnection(_connectionString))
            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = "INSERT INTO ForgottenPasswords (Token, UserId, TimeStamp) VALUES " +
                                  "(@token, @userId, @timestamp)";
                cmd.Parameters.AddWithValue("@token", guid);
                cmd.Parameters.AddWithValue("@userId", user.Id);
                cmd.Parameters.AddWithValue("@timestamp", DateTime.Now);
                connection.Open();
                cmd.ExecuteNonQuery();
            }

            return new UserGuid
            {
                User = user,
                Guid = guid
            };
        }

        public ForgottenPassword GetForgottenPassword(string token)
        {
            using (var connection = new SqlConnection(_connectionString))
            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = "SELECT * FROM ForgottenPasswords fg JOIN Users u ON " +
                                  "u.Id = fg.UserId WHERE Token = @token";
                cmd.Parameters.AddWithValue("@token", token);
                connection.Open();
                var reader = cmd.ExecuteReader();
                if (!reader.Read())
                {
                    return null;
                }

                return new ForgottenPassword
                {
                    Guid = Guid.Parse((string)reader["Token"]),
                    Timestamp = (DateTime)reader["Timestamp"],
                    Email = (string)reader["Email"]
                };
            }
        }

        public void ResetPassword(string token, string password)
        {
            string salt = PasswordHelper.GenerateSalt();
            string passwordHash = PasswordHelper.HashPassword(password, salt);
            int userId = GetIdFromToken(token);
            using (SqlConnection connection = new SqlConnection(_connectionString))
            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = "UPDATE Users SET PasswordHash = @hash, Salt = @salt WHERE ID " +
                                  "= @id";
                cmd.Parameters.AddWithValue("@hash", passwordHash);
                cmd.Parameters.AddWithValue("@salt", salt);
                cmd.Parameters.AddWithValue("@id", userId);
                connection.Open();
                cmd.ExecuteNonQuery();
            }

        }

        private int GetIdFromToken(string token)
        {
            using (SqlConnection connection = new SqlConnection(_connectionString))
            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = "SELECT UserId FROM ForgottenPasswords WHERE Token = @token";
                cmd.Parameters.AddWithValue("@token", token);
                connection.Open();
                return (int)cmd.ExecuteScalar();
            }
        }


    }

    public class UserGuid
    {
        public Guid Guid { get; set; }
        public User User { get; set; }
    }

    public class ForgottenPassword
    {
        public Guid Guid { get; set; }
        public DateTime Timestamp { get; set; }
        public string Email { get; set; }
    }
}
