using JwtRefreshToken101.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtRefreshToken101.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmployeesController : ControllerBase
    {
        private static List<EmployeesDetailsForAdmin> employees= new List<EmployeesDetailsForAdmin>();
        private static List<EmployeesDetailsForUsers> employeeUser= new List<EmployeesDetailsForUsers>();
        static EmployeesController() {
           
            for(int i=1; i<= 10; i++)
            {
                employeeUser.Add(new EmployeesDetailsForUsers
                {
                    EmployeeId = i,
                    UserName = "Luke A"+ i,
                    Role = "Data-Engineer Sector A "+i
                });
            }

            for (int i = 1; i <= 10; i++)
            {
                employees.Add(new EmployeesDetailsForAdmin
                {
                    EmployeeId = i,
                    UserName = "Luke A" + i,
                    AdminDataFeed=1254 + i,
                    Salary=23000 + i,
                    Role = "Data-Engineer Sector A " + i
                });
            }


        }

        [Authorize(AuthenticationSchemes =JwtBearerDefaults.AuthenticationScheme, Roles ="Admin")]
        [HttpGet]
        [Route("employeesdetails-adminOnly")]
        public IActionResult GetEmployees()
        {
                   return Ok(employees);
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin, User")]
        [HttpGet]
        [Route("employeesdetails")]
        public IActionResult GetEmployee()
        {
              return Ok(employeeUser);
        }


        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
        [HttpDelete("{id:int}")]
         public IActionResult removeEmployee(int id)
        {
            
            var emp = employees.Where(e => e.EmployeeId == id)
                      .FirstOrDefault();
            var emp1 = employeeUser.Where(e => e.EmployeeId == id)
                      .FirstOrDefault();

            if (emp != null && emp1 != null)
            {
                employees.Remove(emp);
                employeeUser.Remove(emp1!);

                return Ok(new AuthResponse { Status = "Success", Message = "employee detils delated successfully" });
            }
            return BadRequest("Id does snot exist");
         }
    }
}
