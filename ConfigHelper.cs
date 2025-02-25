using Microsoft.Extensions.Configuration;
using System;
using System.IO;

public class ConfigHelper
{
    private static IConfigurationRoot configuration;

    static ConfigHelper()
    {
        var builder = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

        configuration = builder.Build();
    }

    public static string GetConfigValue(string key)
    {
        return configuration[$"PdndConfig:{key}"];
    }
}
