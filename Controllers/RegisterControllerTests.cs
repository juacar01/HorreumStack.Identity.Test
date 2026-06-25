using HorreumStack.Identity.Controllers;
using HorreumStack.Identity.Core.Application.Features.Register;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace HorreumStack.Identity.Tests.Controllers;

public class RegisterControllerTests
{
    private readonly Mock<IRegisterService> _registerServiceMock;
    private readonly RegisterController _controller;

    public RegisterControllerTests()
    {
        _registerServiceMock = new Mock<IRegisterService>();
        _controller = new RegisterController(_registerServiceMock.Object);
    }

    [Fact]
    public async Task Register_ShouldReturnOkWithResult_WhenModelIsValid()
    {
        // Arrange
        var model = new RegisterVm
        {
            Nombre = "John",
            Apellidos = "Doe",
            Email = "john.doe@example.com",
            Password = "SecurePassword123!"
        };

        var expectedResult = new RegisterVm
        {
            Nombre = model.Nombre,
            Apellidos = model.Apellidos,
            Email = model.Email
        };

        _registerServiceMock
            .Setup(s => s.RegisterAsync(model, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedResult);

        // Act
        var result = await _controller.Register(model, CancellationToken.None);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var returnedVal = Assert.IsType<RegisterVm>(okResult.Value);
        Assert.Equal(expectedResult.Email, returnedVal.Email);
        Assert.Equal(expectedResult.Nombre, returnedVal.Nombre);
    }

    [Fact]
    public async Task Register_ShouldReturnBadRequest_WhenModelIsNull()
    {
        // Act
        var result = await _controller.Register(null!, CancellationToken.None);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Datos inválidos.", badRequestResult.Value);
    }
}
