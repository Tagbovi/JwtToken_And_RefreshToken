namespace JwtRefreshToken101.Models
{
    public class EmployeesDetailsForAdmin
    {
        public int EmployeeId { get; set; }
        public string? UserName { get; set; }
       
        public int? AdminDataFeed { get; set; }
        public decimal Salary { get; set; }
        public string? Role { get; set; }
    }
}
