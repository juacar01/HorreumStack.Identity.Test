using HorreumStack.Identity.Controllers;
using HorreumStack.Infrastructure.Persistence;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;
using Xunit;

namespace HorreumStack.Identity.Tests.Controllers;

public class HealthControllerTests
{
    [Fact]
    public async Task CheckHealth_ShouldReturnOk_WhenDatabaseIsHealthy()
    {
        // Arrange
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        using var dbContext = new ApplicationDbContext(options);
        // Ensure database is created so connection check succeeds
        await dbContext.Database.EnsureCreatedAsync();

        var controller = new HealthController(dbContext);

        // Act
        var result = await controller.CheckHealth();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        dynamic data = okResult.Value!;
        Assert.Equal("Healthy", (string)data.GetType().GetProperty("Status").GetValue(data));
        Assert.Equal("Connected", (string)data.GetType().GetProperty("Database").GetValue(data));
    }
}
