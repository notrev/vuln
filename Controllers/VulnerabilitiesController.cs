using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Vuln.Models;
using Vuln.Services;

namespace Vuln.Controllers
{
    [ApiController]
    [Route("vulnerabilities")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public class VulnerabilitiesController : ControllerBase
    {
        private readonly ILogger<VulnerabilityService> _logger;
        private readonly IVulnerabilityService _vulnerabilityService;

        public VulnerabilitiesController(IVulnerabilityService vulnerabilityService, ILogger<VulnerabilityService> logger)
        {
            _vulnerabilityService = vulnerabilityService;
            _logger = logger;
        }

        [HttpGet]
        [Authorize(Roles = "Reader")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<List<Vulnerability>>> Get(int offset = 0, int limit = 10)
        {
            return Ok(await _vulnerabilityService.GetVulnerabilities(offset, limit));
        }

        [HttpGet("{id}")]
        [Authorize(Roles = "Reader")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<Vulnerability>> Get(string id)
        {
            Vulnerability? vulnerability = await _vulnerabilityService.GetVulnerability(id);

            if (vulnerability != null) {
                return Ok(vulnerability);
            }
            return NotFound();
        }

        [HttpPost]
        [Authorize(Roles = "Writer")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status409Conflict)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult> Post([FromBody] Vulnerability vulnerability)
        {
            // TODO: validate input using JSON schema
            try
            {
                await _vulnerabilityService.AddVulnerability(vulnerability);
                return Created();
            }
            catch (VulnerabilityDuplicateException)
            {
                return Conflict();
            }
            catch (Exception e)
            {
                _logger.LogError($"Error when adding new vulnerability: {e.Message}");
                return StatusCode(500);
            }
        }

        [HttpPut("{id}")]
        [Authorize(Roles = "Writer")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult> Put(string id, [FromBody] Vulnerability vulnerability)
        {
            // TODO: validate input using JSON schema
            try
            {
                await _vulnerabilityService.UpdateVulnerability(id, vulnerability);
                return NoContent();
            }
            catch (VulnerabilityNotFoundException)
            {
                return NotFound();
            }
            catch (Exception e)
            {
                _logger.LogError($"Error when updating vulnerability: {e.Message}");
                return StatusCode(500);
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = "Writer")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult> Delete(string id) {
            try
            {
                await _vulnerabilityService.DeleteVulnerability(id);
                return NoContent();
            }
            catch (VulnerabilityNotFoundException)
            {
                return NotFound();
            }
            catch (Exception e)
            {
                _logger.LogError($"Error when deleting vulnerability: {e.Message}");
                return StatusCode(500);
            }
        }
    }
}