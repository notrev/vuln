using Microsoft.AspNetCore.Mvc;
using Vuln.Models;
using Vuln.Services;

namespace Vuln.Controllers
{
    [ApiController]
    [Route("vulnerabilities")]
    public class VulnerabilitiesController : ControllerBase
    {
        private readonly VulnerabilityService _vulnerabilityService;

        public VulnerabilitiesController(VulnerabilityService vulnerabilityService)
        {
            _vulnerabilityService = vulnerabilityService;
        }

        [HttpGet]
        public ActionResult<List<Vulnerability>> Get()
        {
            return Ok(_vulnerabilityService.GetVulnerabilities());
        }

        [HttpGet("{id}")]
        public ActionResult<List<Vulnerability>> Get(string id)
        {
            Vulnerability? vulnerability = _vulnerabilityService.GetVulnerability(id);

            if (vulnerability != null) {
                return Ok(vulnerability);
            }
            return NotFound();
        }

        [HttpPost]
        public void Post([FromBody] Vulnerability vulnerability)
        {
            // TODO: validate input using JSON schema
            _vulnerabilityService.AddVulnerability(vulnerability);
        }

        [HttpPut("{id}")]
        public void Put(string id, [FromBody] Vulnerability vulnerability)
        {
            // TODO: validate input using JSON schema
            _vulnerabilityService.UpdateVulnerability(id, vulnerability);
        }

        [HttpDelete("{id}")]
        public void Delete(string id) {
            _vulnerabilityService.DeleteVulnerability(id);
        }
    }
}