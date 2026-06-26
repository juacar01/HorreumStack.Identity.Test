using HorreumStack.Domain.Entities;
using HorreumStack.Identity.Controllers;
using HorreumStack.Identity.Core.Application.Features.Login;
using HorreumStack.Identity.Core.Application.Features.Register;
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

public class AuthControllerTests
{
    private readonly Mock<IUnitOfWork> _unitOfWorkMock;
    private readonly Mock<IAsyncRepository<User>> _userRepositoryMock;
    private readonly Mock<IConfiguration> _configurationMock;
    private readonly Mock<IPasswordHasher> _passwordHasherMock;
    private readonly Mock<IRegisterService> _registerServiceMock;
    private readonly AuthController _controller;

    public AuthControllerTests()
    {
        _unitOfWorkMock = new Mock<IUnitOfWork>();
        _userRepositoryMock = new Mock<IAsyncRepository<User>>();
        _configurationMock = new Mock<IConfiguration>();
        _passwordHasherMock = new Mock<IPasswordHasher>();
        _registerServiceMock = new Mock<IRegisterService>();

        _unitOfWorkMock.Setup(u => u.Repository<User>()).Returns(_userRepositoryMock.Object);

        // Setup common config values needed for JWT generation
        _configurationMock.Setup(c => c["Jwt:SecretKey"]).Returns("ThisIsATestSecretKeyForJwtAuthentication32BytesOrLonger");
        _configurationMock.Setup(c => c["Jwt:Issuer"]).Returns("HorreumStack.Identity.Test");
        _configurationMock.Setup(c => c["Jwt:Audience"]).Returns("HorreumStack.Clients.Test");
        _configurationMock.Setup(c => c["Jwt:ExpirationMinutes"]).Returns("60");

        _controller = new AuthController(
            _unitOfWorkMock.Object,
            _configurationMock.Object,
            _passwordHasherMock.Object,
            _registerServiceMock.Object
        );

        // Configurar un HttpContext simulado por defecto para evitar NullReferenceException con las Cookies
        var httpContext = new DefaultHttpContext();
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
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
        Assert.Equal(model.Email, (string)val.GetType().GetProperty("Email").GetValue(val));
        Assert.Equal(user.Username, (string)val.GetType().GetProperty("Username").GetValue(val));

        // Verificar que la cookie fue añadida
        var setCookieHeader = _controller.HttpContext.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains("AuthToken=", setCookieHeader);
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

    [Fact]
    public async Task RefreshToken_ShouldReturnOkWithNewToken_WhenTokenIsValidOrExpired()
    {
        // Arrange
        var secretKey = "ThisIsATestSecretKeyForJwtAuthentication32BytesOrLonger";
        var issuer = "HorreumStack.Identity.Test";
        var audience = "HorreumStack.Clients.Test";
        var userId = Guid.NewGuid();
        var user = new User
        {
            Id = userId,
            Email = "test@example.com",
            Username = "testuser"
        };

        var token = JwtHelper.GenerateToken(
            userId.ToString(),
            user.Email,
            user.Username,
            secretKey,
            issuer,
            audience,
            30
        );

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["Authorization"] = $"Bearer {token}";
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };

        _userRepositoryMock
            .Setup(r => r.GetEntityAsync(
                It.IsAny<Expression<Func<User, bool>>>(),
                It.IsAny<List<Expression<Func<User, object>>>>(),
                It.IsAny<bool>()))
            .ReturnsAsync(user);


        // Act
        var result = await _controller.RefreshToken();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        dynamic val = okResult.Value!;
        Assert.Equal(user.Email, (string)val.GetType().GetProperty("Email").GetValue(val));
        Assert.Equal(user.Username, (string)val.GetType().GetProperty("Username").GetValue(val));

        // Verificar que la nueva cookie fue añadida
        var setCookieHeader = _controller.HttpContext.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains("AuthToken=", setCookieHeader);
    }

    [Fact]
    public async Task RefreshToken_ShouldReturnBadRequest_WhenAuthorizationHeaderIsMissing()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };

        // Act
        var result = await _controller.RefreshToken();

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Token de autenticación no provisto en cookies ni en cabecera.", badRequestResult.Value);
    }

    [Fact]
    public void Logout_ShouldReturnOk_AndRemoveCookie()
    {
        // Act
        var result = _controller.Logout();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        dynamic val = okResult.Value!;
        Assert.Equal("Sesión cerrada correctamente", (string)val.GetType().GetProperty("Message").GetValue(val));

        // Verificar que la cookie fue eliminada
        var setCookieHeader = _controller.HttpContext.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains("AuthToken=;", setCookieHeader);
    }
}
