using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;

if (args.Length != 2)
{
    Console.Error.WriteLine("usage: DummyMetadataScanner <assembly> <output-json>");
    return 2;
}

using var stream = File.OpenRead(args[0]);
using var pe = new PEReader(stream);
if (!pe.HasMetadata)
{
    Console.Error.WriteLine("input has no managed metadata");
    return 2;
}

var reader = pe.GetMetadataReader();
var parentByChild = new Dictionary<TypeDefinitionHandle, TypeDefinitionHandle>();
foreach (var handle in reader.TypeDefinitions)
{
    var def = reader.GetTypeDefinition(handle);
    foreach (var child in def.GetNestedTypes())
        parentByChild[child] = handle;
}

string FullName(TypeDefinitionHandle handle)
{
    var def = reader.GetTypeDefinition(handle);
    var name = reader.GetString(def.Name);
    if (parentByChild.TryGetValue(handle, out var parent))
        return FullName(parent) + "." + name;
    var ns = reader.GetString(def.Namespace);
    return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
}

var rows = new List<object>();
foreach (var handle in reader.TypeDefinitions)
{
    var def = reader.GetTypeDefinition(handle);
    var name = reader.GetString(def.Name);
    var ns = reader.GetString(def.Namespace);
    string? parent = parentByChild.TryGetValue(handle, out var parentHandle)
        ? FullName(parentHandle)
        : null;
    rows.Add(new
    {
        metadata_rid = MetadataTokens.GetRowNumber(handle),
        type = FullName(handle),
        short_name = name,
        @namespace = ns,
        enclosing_type = parent,
        nested = parent is not null,
    });
}

var doc = new
{
    schema = 1,
    assembly = Path.GetFileName(args[0]),
    type_count = rows.Count,
    types = rows,
};
var options = new JsonSerializerOptions { WriteIndented = true };
File.WriteAllText(args[1], JsonSerializer.Serialize(doc, options) + Environment.NewLine);
return 0;
