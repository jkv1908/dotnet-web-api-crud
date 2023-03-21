using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace UserApi.Models;

public partial class NodeContext : DbContext
{
    public NodeContext()
    {
    }

    public NodeContext(DbContextOptions<NodeContext> options)
        : base(options)
    {
    }

    public virtual DbSet<User> Users { get; set; }

    // protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    //     => optionsBuilder.UseMySQL("Server=localhost;port=3306;Database=node;uid=node_user;password=node_user;");

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.UserId).HasName("PRIMARY");

            entity.ToTable("user");

            entity.HasIndex(e => e.Email, "email_UNIQUE").IsUnique();

            entity.HasIndex(e => e.Username, "username_UNIQUE").IsUnique();

            entity.Property(e => e.UserId).HasColumnName("user_id");
            entity.Property(e => e.Email)
                .HasMaxLength(400)
                .HasColumnName("email");
            entity.Property(e => e.Password)
                .HasMaxLength(400)
                .HasColumnName("password");
            entity.Property(e => e.Username)
                .HasMaxLength(45)
                .HasColumnName("username");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
