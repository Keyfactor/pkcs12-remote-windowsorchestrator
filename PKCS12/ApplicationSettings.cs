using System.IO;
using System.Text;

using Newtonsoft.Json;

namespace Keyfactor.Extensions.Orchestrator.PKCS12
{
    class ApplicationSettings
    {
        public static bool UseSudo { get; set; }
        public static bool UseSeparateUploadFilePath { get; set; }
        public static string SeparateUploadFilePath { get; set; }
        public static bool UseSFTP { get; set; }
        public static bool UseSCP { get; set; }

        public static void Initialize(string currLocation)
        {
            string configContents = string.Empty;
            string currDir = Path.GetDirectoryName(currLocation);

            if (!File.Exists($@"{currDir}\config.json"))
                throw new PKCS12Exception($"config.json file does not exist in {currDir}");

            using (StreamReader sr = new StreamReader($@"{currDir}\config.json"))
            {
                configContents = sr.ReadToEnd();
            }

            dynamic jsonContents = JsonConvert.DeserializeObject(configContents);

            ValidateConfig(jsonContents);

            UseSudo = jsonContents.UseSudo.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            UseSeparateUploadFilePath = jsonContents.UseSeparateUploadFilePath.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            SeparateUploadFilePath = AddTrailingSlash(jsonContents.SeparateUploadFilePath.Value);
            UseSFTP = jsonContents.UseSFTP == null || !jsonContents.UseSFTP.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase) ? false : true;
            UseSCP = jsonContents.UseSCP == null || !jsonContents.UseSCP.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase) ? false : true;
            UseSFTP = !UseSFTP && !UseSCP ? true : UseSFTP;
        }

        private static string AddTrailingSlash(string path)
        {
            return path.Substring(path.Length - 1, 1) == @"/" ? path : path += @"/";
        }

        private static void ValidateConfig(dynamic jsonContents)
        {
            string errors = string.Empty;

            if (jsonContents.UseSudo == null)
                errors += "UseSudo, ";
            if (jsonContents.UseSeparateUploadFilePath == null)
                errors += "UseSeparateUploadFilePath, ";
            if (jsonContents.SeparateUploadFilePath == null)
                errors += "SeparateUploadFilePath, ";

            if (errors.Length > 0)
                throw new PKCS12Exception($"The following configuration items are missing from the config.json file: {errors.Substring(0, errors.Length-2)}");
        }
    }
}

