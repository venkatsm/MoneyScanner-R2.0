//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace MoneyScannerApp.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class Coupon
    {
        public int CouponId { get; set; }
        public string CouponLogo { get; set; }
        public string CouponDescription { get; set; }
        public string CouponCode { get; set; }
        public Nullable<System.DateTime> StartDate { get; set; }
        public Nullable<System.DateTime> ExpiresOn { get; set; }
    }
}
