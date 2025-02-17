using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;

namespace Vuln.Services
{
    public class SchemaValidator
    {
        private readonly JSchema _vulnerabilitySchema;

        public SchemaValidator()
        {
            JSchemaUrlResolver resolver = new JSchemaUrlResolver();
            var schemaPath = Path.Combine(AppContext.BaseDirectory, "Schemas/sdos/vulnerability.json");
            try
            {
                var schema = File.ReadAllText(schemaPath);
                _vulnerabilitySchema = JSchema.Parse(schema, new JSchemaReaderSettings
                {
                    Resolver = resolver,
                    BaseUri = new Uri(schemaPath)
                });
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error loading schema: {e.Message}");
                throw new Exception("Error loading schema");
            }
        }

        public bool ValidateVulnerability(string data, out IList<string> errors)
        {
            var json = JObject.Parse(data);
            return json.IsValid(_vulnerabilitySchema, out errors);
        }
    }
}