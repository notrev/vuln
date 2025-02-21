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
        private readonly VulnerabilityService _vulnerabilityService;

        public VulnerabilitiesController(VulnerabilityService vulnerabilityService)
        {
            _vulnerabilityService = vulnerabilityService;
        }

        [HttpGet]
        [Authorize(Roles = "Reader")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public ActionResult<List<Vulnerability>> Get()
        {
            return Ok(_vulnerabilityService.GetVulnerabilities());
        }

        [HttpGet("{id}")]
        [Authorize(Roles = "Reader")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult<List<Vulnerability>> Get(string id)
        {
            Vulnerability? vulnerability = _vulnerabilityService.GetVulnerability(id);

            if (vulnerability != null) {
                return Ok(vulnerability);
            }
            return NotFound();
        }

        [HttpPost]
        [Authorize(Roles = "Writer")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public ActionResult Post([FromBody] Vulnerability vulnerability)
        {
            // TODO: validate input using JSON schema
            try
            {
                _vulnerabilityService.AddVulnerability(vulnerability);
                return Created();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error when adding new vulnerability: {e.Message}");
                return StatusCode(500);
            }
        }

        [HttpPut("{id}")]
        [Authorize(Roles = "Writer")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public ActionResult Put(string id, [FromBody] Vulnerability vulnerability)
        {
            // TODO: validate input using JSON schema
            try
            {
                _vulnerabilityService.UpdateVulnerability(id, vulnerability);
                return StatusCode(204);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error when adding new vulnerability: {e.Message}");
                return StatusCode(500);
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = "Writer")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public ActionResult Delete(string id) {
            try
            {
                _vulnerabilityService.DeleteVulnerability(id);
                return NoContent();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error when adding new vulnerability: {e.Message}");
                return StatusCode(500);
            }
        }
    }
}