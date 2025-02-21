using Microsoft.AspNetCore.Mvc;
using Moq;
using Sprache;
using Vuln.Controllers;
using Vuln.Data;
using Vuln.Models;
using Vuln.Services;
using Xunit;

namespace Vuln.Tests.Controllers
{
    public class VulnerabilitiesControllerTests
    {
        private readonly Mock<IVulnerabilityService> _mockVulnerabilityService;
        private readonly Mock<ILogger<VulnerabilityService>> _mockLogger;
        private readonly VulnerabilitiesController _controller;

        public VulnerabilitiesControllerTests()
        {
            _mockVulnerabilityService = new Mock<IVulnerabilityService>();
            _mockLogger = new Mock<ILogger<VulnerabilityService>>();
            _controller = new VulnerabilitiesController(_mockVulnerabilityService.Object, _mockLogger.Object);
        }

        [Fact]
        public async Task Get_ReturnsOkResult_WithListOfVulnerabilities()
        {
            var dateTime = DateTime.UtcNow;
            var vulnerabilities = new List<Vulnerability> {
                new Vulnerability {
                    Id = "1",
                    Name = "Test Vulnerability",
                    Created = dateTime,
                    Modified = dateTime,
                },
                new Vulnerability {
                    Id = "2",
                    Name = "Test Vulnerability",
                    Created = dateTime,
                    Modified = dateTime,
                }
            };
            _mockVulnerabilityService.Setup(service => service.GetVulnerabilities(It.IsAny<int>(), It.IsAny<int>()))
                .ReturnsAsync(vulnerabilities);

            var result = await _controller.Get();

            // Check if the result is of type OkObjectResult
            var okResult = result.Result as OkObjectResult;
            Assert.NotNull(okResult);
            Assert.IsType<OkObjectResult>(okResult);

            // Check if the value is not null and is of the expected type
            var returnValue = okResult.Value as List<Vulnerability>;
            Assert.NotNull(returnValue);
            Assert.Equal(2, returnValue.Count);
        }

        [Fact]
        public async Task Get_WithId_ReturnsOkResult_WithVulnerability()
        {
            var dateTime = DateTime.UtcNow;
            var vulnerability = new Vulnerability {
                Id = "1",
                Name = "Test Vulnerability",
                Created = dateTime,
                Modified = dateTime,
            };
            
            _mockVulnerabilityService.Setup(service => service.GetVulnerability("1"))
                .ReturnsAsync(vulnerability);

            var result = await _controller.Get("1");

            // Check if the result is of type OkObjectResult
            var okResult = result.Result as OkObjectResult;
            Assert.NotNull(okResult);
            Assert.IsType<OkObjectResult>(okResult);

            // Check if the value is not null and is of the expected type
            var returnValue = okResult.Value as Vulnerability;
            Assert.NotNull(returnValue);
            Assert.Equal("1", returnValue.Id);
        }

        [Fact]
        public async Task Get_WithId_ReturnsNotFoundResult_WhenVulnerabilityNotFound()
        {
            _mockVulnerabilityService.Setup(service => service.GetVulnerability("1"))
                .ReturnsAsync(null as Vulnerability);

            var result = await _controller.Get("1");

            Assert.IsType<NotFoundResult>(result.Result);
        }

        [Fact]
        public async Task Post_ReturnsCreatedResult_WhenVulnerabilityIsAdded()
        {
            var dateTime = DateTime.UtcNow;
            var vulnerability = new Vulnerability {
                Id = "1",
                Name = "Test Vulnerability",
                Created = dateTime,
                Modified = dateTime,
            };;

            var result = await _controller.Post(vulnerability);

            Assert.IsType<CreatedResult>(result);
        }

        [Fact]
        public async Task Post_ReturnsConflictResult_WhenVulnerabilityDuplicateExceptionIsThrown()
        {
            var dateTime = DateTime.UtcNow;
            var vulnerability = new Vulnerability {
                Id = "1",
                Name = "Test Vulnerability",
                Created = dateTime,
                Modified = dateTime,
            };

            _mockVulnerabilityService.Setup(service => service.AddVulnerability(vulnerability))
                .ThrowsAsync(new VulnerabilityDuplicateException(vulnerability.Id));

            var result = await _controller.Post(vulnerability);

            Assert.IsType<ConflictResult>(result);
        }

        [Fact]
        public async Task Put_ReturnsNoContentResult_WhenVulnerabilityIsUpdated()
        {
            var dateTime = DateTime.UtcNow;
            var vulnerability = new Vulnerability {
                Id = "1",
                Name = "Test Vulnerability",
                Created = dateTime,
                Modified = dateTime,
            };

            var result = await _controller.Put("1", vulnerability);
            Assert.IsType<NoContentResult>(result);
        }

        [Fact]
        public async Task Put_ReturnsNotFoundResult_WhenVulnerabilityNotFoundExceptionIsThrown()
        {
            var dateTime = DateTime.UtcNow;
            var vulnerability = new Vulnerability {
                Id = "1",
                Name = "Test Vulnerability",
                Created = dateTime,
                Modified = dateTime,
            };

            _ = _mockVulnerabilityService.Setup(service => service.UpdateVulnerability("1", vulnerability))
                .ThrowsAsync(new VulnerabilityNotFoundException("1"));

            var result = await _controller.Put("1", vulnerability);

            Assert.IsType<NotFoundResult>(result);
        }

        [Fact]
        public async Task Delete_ReturnsNoContentResult_WhenVulnerabilityIsDeleted()
        {
            var result = await _controller.Delete("1");

            Assert.IsType<NoContentResult>(result);
        }

        [Fact]
        public async Task Delete_ReturnsNotFoundResult_WhenVulnerabilityNotFoundExceptionIsThrown()
        {
            _ = _mockVulnerabilityService.Setup(service => service.DeleteVulnerability("1"))
                .ThrowsAsync(new VulnerabilityNotFoundException("1"));

            var result = await _controller.Delete("1");

            Assert.IsType<NotFoundResult>(result);
        }
    }
}