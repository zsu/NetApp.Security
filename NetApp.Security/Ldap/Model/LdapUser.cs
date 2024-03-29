﻿using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetApp.Security
{
    // Add profile data for application users by adding properties to the LdapUser class
    public class LdapUser : ILdapEntry
    {
        [NotMapped]
        public string ObjectSid { get; set; }

        [NotMapped]
        public string ObjectGuid { get; set; }

        [NotMapped]
        public string ObjectCategory { get; set; }

        [NotMapped]
        public string ObjectClass { get; set; }

        [NotMapped]
        [Display(Name = "Password")]
        [Required(ErrorMessage = "You must enter your password!")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [NotMapped]
        public string Name { get; set; }

        [NotMapped]
        public string CommonName { get; set; }

        [NotMapped]
        public string DistinguishedName { get; set; }

        [NotMapped]
        public string SamAccountName { get; set; }

        [NotMapped]
        public int SamAccountType { get; set; }

        [NotMapped]
        public string[] MemberOf { get; set; }

        [NotMapped]
        public bool IsDomainAdmin { get; set; }

        [NotMapped]
        public bool MustChangePasswordOnNextLogon { get; set; }

        [NotMapped]
        public string UserPrincipalName { get; set; }

        [NotMapped]
        public string DisplayName { get; set; }

        [NotMapped]
        [Required(ErrorMessage = "You must enter your first name!")]
        public string FirstName { get; set; }

        [NotMapped]
        [Required(ErrorMessage = "You must enter your last name!")]
        public string LastName { get; set; }

        [NotMapped]
        public string FullName => String.IsNullOrWhiteSpace(MiddleName) ? $"{this.FirstName?.Trim()} {this.LastName?.Trim()}" : $"{this.FirstName?.Trim()} {MiddleName?.Trim()} {this.LastName?.Trim()}";

        [NotMapped]
        [Required(ErrorMessage = "You must enter your email address!")]
        [EmailAddress(ErrorMessage = "You must enter a valid email address.")]
        public string EmailAddress { get; set; }

        [NotMapped]
        public string Description { get; set; }

        [NotMapped]
        public string Phone { get; set; }

        [NotMapped]
        public LdapAddress Address { get; set; }

        //public override string SecurityStamp => Guid.NewGuid().ToString("D");

        public virtual string UserName
        {
            get; set;
        }

        //public virtual string NormalizedUserName => this.UserName;

        //public virtual string NormalizedEmail => this.EmailAddress;

        //public override string Id => Guid.NewGuid().ToString("D");

        //public virtual string Email => this.EmailAddress;
        [NotMapped]
        public string EmployeeId { get; set; }
        [NotMapped]
        public string Title { get; set; }
        [NotMapped]
        public string Manager { get; set; }
        [NotMapped]
        public string Division { get; set; }
        [NotMapped]
        public string Department { get; set; }
        [NotMapped]
        public string AccountFlag { get; set; }
        [NotMapped]
        public string MiddleName { get; set; }
        [NotMapped]
        public string EmployeeType { get; set; }
        [NotMapped]
        public bool Disabled { get => (Convert.ToInt32(AccountFlag) & 2) > 0; }
    }

    public class LdapAddress
    {
        public string Street { get; set; }
        public string PostalCode { get; set; }
        public string City { get; set; }
        public string StateName { get; set; }
        public string CountryName { get; set; }
        public string CountryCode { get; set; }
    }

}