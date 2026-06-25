using HorreumStack.Domain.Entities;
using HorreumStack.Identity.Controllers;
using HorreumStack.Identity.Core.Application.Features.Login;
using HorreumStack.Infrastructure.Repositories;
using HorreumStack.Utilities.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace HorreumStack.Identity.Tests.Controllers;

public class LoginControllerTests
{
    private readonly Mock<IUnitOfWork> _unitOfWorkMock;
    private readonly Mock<IAsyncRepository<User>> _userRepositoryMock;
    private readonly Mock<IConfiguration> _configurationMock;
    private readonly Mock<IPasswordHasher> _passwordHasherMock;
    private readonly LoginController _controller;

    public LoginControllerTests()
    {
        _unitOfWorkMock = new Mock<IUnitOfWork>();
        _userRepositoryMock = new Mock<IAsyncRepository<User>>();
        _configurationMock = new Mock<IConfiguration>();
        _passwordHasherMock = new Mock<IPasswordHasher>();

        _unitOfWorkMock.Setup(u => u.Repository<User>()).Returns(_userRepositoryMock.Object);

        // Setup common config values needed for JWT generation
        _configurationMock.Setup(c => c["Jwt:SecretKey"]).Returns("ThisIsATestSecretKeyForJwtAuthentication32BytesOrLonger");
        _configurationMock.Setup(c => c["Jwt:Issuer"]).Returns("HorreumStack.Identity.Test");
        _configurationMock.Setup(c => c["Jwt:Audience"]).Returns("HorreumStack.Clients.Test");
        _configurationMock.Setup(c => c["Jwt:ExpirationMinutes"]).Returns("60");

        _controller = new LoginController(
            _unitOfWorkMock.Object,
            _configurationMock.Object,
            _passwordHasherMock.Object
        );
    }

    [Fact]
    public async Task Login_ShouldReturnOkWithToken_WhenCredentialsAreValid()
    {
        // Arrange
        var model = new LoginVm { Email = "test@example.com", Password = "ValidPassword123" };
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = model.Email,
            Username = "testuser",
            PasswordHash = "hashed_password"
        };

        _userRepositoryMock
            .Setup(r => r.GetEntityAsync(
                It.IsAny<Expression<Func<User, bool>>>(),
                It.IsAny<List<Expression<Func<User, object>>>>(),
                It.IsAny<bool>()))
            .ReturnsAsync(user);

        _passwordHasherMock
            .Setup(h => h.VerifyPassword(model.Password, user.PasswordHash))
            .Returns(true);

        // Act
        var result = await _controller.Login(model, CancellationToken.None);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        dynamic val = okResult.Value!;
        Assert.NotNull(val.GetType().GetProperty("Token").GetValue(val));
        Assert.Equal(model.Email, (string)val.GetType().GetProperty("Email").GetValue(val));
        Assert.Equal(user.Username, (string)val.GetType().GetProperty("Username").GetValue(val));
    }

    [Fact]
    public async Task Login_ShouldReturnUnauthorized_WhenUserNotFound()
    {
        // Arrange
        var model = new LoginVm { Email = "nonexistent@example.com", Password = "Password123" };

        _userRepositoryMock
            .Setup(r => r.GetEntityAsync(
                It.IsAny<Expression<Func<User, bool>>>(),
                null,
                true))
            .ReturnsAsync((User)null!);

        // Act
        var result = await _controller.Login(model, CancellationToken.None);

        // Assert
        var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("Credenciales inválidas.", unauthorizedResult.Value);
    }

    [Fact]
    public async Task Login_ShouldReturnUnauthorized_WhenPasswordIsIncorrect()
    {
        // Arrange
        var model = new LoginVm { Email = "test@example.com", Password = "WrongPassword" };
        var user = new User { Email = model.Email, PasswordHash = "hashed_password" };

        _userRepositoryMock
            .Setup(r => r.GetEntityAsync(
                It.IsAny<Expression<Func<User, bool>>>(),
                It.IsAny<List<Expression<Func<User, object>>>>(),
                It.IsAny<bool>()))
            .ReturnsAsync(user);

        _passwordHasherMock
            .Setup(h => h.VerifyPassword(model.Password, user.PasswordHash))
            .Returns(false);

        // Act
        var result = await _controller.Login(model, CancellationToken.None);

        // Assert
        var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("Credenciales inválidas.", unauthorizedResult.Value);
    }

    [Fact]
    public async Task ValidateToken_ShouldReturnOkWithClaims_WhenTokenIsValid()
    {
        // Arrange
        var secretKey = "ThisIsATestSecretKeyForJwtAuthentication32BytesOrLonger";
        var issuer = "HorreumStack.Identity.Test";
        var audience = "HorreumStack.Clients.Test";

        var token = JwtHelper.GenerateToken(
            Guid.NewGuid().ToString(),
            "test@example.com",
            "testuser",
            secretKey,
            issuer,
            audience,
            30
        );

        // Act
        var result = _controller.ValidateToken(token);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        dynamic val = okResult.Value!;
        Assert.True((bool)val.GetType().GetProperty("Valid").GetValue(val));
        var claims = val.GetType().GetProperty("Claims").GetValue(val);
        Assert.NotNull(claims);
    }

    [Fact]
    public async Task ValidateToken_ShouldReturnBadRequest_WhenTokenIsInvalid()
    {
        // Arrange
        var invalidToken = "invalid.jwt.token";

        // Act
        var result = _controller.ValidateToken(invalidToken);

        // Assert
        var badResult = Assert.IsType<BadRequestObjectResult>(result);
        dynamic val = badResult.Value!;
        Assert.False((bool)val.GetType().GetProperty("Valid").GetValue(val));
        Assert.Equal("Token inválido o expirado.", (string)val.GetType().GetProperty("Message").GetValue(val));
    }
}
