using System.Collections.Immutable;
using System.Reflection;
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

string FullTypeReference(TypeReferenceHandle handle)
{
    var tr = reader.GetTypeReference(handle);
    var name = reader.GetString(tr.Name);
    if (tr.ResolutionScope.Kind == HandleKind.TypeReference)
        return FullTypeReference((TypeReferenceHandle)tr.ResolutionScope) + "." + name;
    var ns = reader.GetString(tr.Namespace);
    return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
}

var provider = new TypeNameProvider(reader, FullName, FullTypeReference);

string EntityTypeName(EntityHandle handle)
{
    return handle.Kind switch
    {
        HandleKind.TypeDefinition => FullName((TypeDefinitionHandle)handle),
        HandleKind.TypeReference => FullTypeReference((TypeReferenceHandle)handle),
        HandleKind.TypeSpecification => reader.GetTypeSpecification((TypeSpecificationHandle)handle)
            .DecodeSignature(provider, null),
        _ => handle.Kind.ToString(),
    };
}

string AttributeTypeName(CustomAttributeHandle handle)
{
    var ca = reader.GetCustomAttribute(handle);
    var ctor = ca.Constructor;
    if (ctor.Kind == HandleKind.MemberReference)
    {
        var mr = reader.GetMemberReference((MemberReferenceHandle)ctor);
        return EntityTypeName(mr.Parent);
    }
    if (ctor.Kind == HandleKind.MethodDefinition)
    {
        var md = reader.GetMethodDefinition((MethodDefinitionHandle)ctor);
        return FullName(md.GetDeclaringType());
    }
    return ctor.Kind.ToString();
}

string Visibility(FieldAttributes attrs)
{
    return (attrs & FieldAttributes.FieldAccessMask) switch
    {
        FieldAttributes.Public => "public",
        FieldAttributes.Private => "private",
        FieldAttributes.Family => "protected",
        FieldAttributes.Assembly => "internal",
        FieldAttributes.FamORAssem => "protected-internal",
        FieldAttributes.FamANDAssem => "private-protected",
        _ => "compiler-controlled",
    };
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
    var fields = new List<object>();
    foreach (var fieldHandle in def.GetFields())
    {
        var field = reader.GetFieldDefinition(fieldHandle);
        string fieldType;
        try
        {
            fieldType = field.DecodeSignature(provider, null);
        }
        catch (BadImageFormatException)
        {
            fieldType = "<signature-decode-error>";
        }
        fields.Add(new
        {
            metadata_rid = MetadataTokens.GetRowNumber(fieldHandle),
            name = reader.GetString(field.Name),
            field_type = fieldType,
            visibility = Visibility(field.Attributes),
            is_static = (field.Attributes & FieldAttributes.Static) != 0,
            is_init_only = (field.Attributes & FieldAttributes.InitOnly) != 0,
            custom_attributes = field.GetCustomAttributes()
                .Select(AttributeTypeName)
                .Distinct()
                .OrderBy(x => x)
                .ToArray(),
        });
    }
    rows.Add(new
    {
        metadata_rid = MetadataTokens.GetRowNumber(handle),
        type = FullName(handle),
        short_name = name,
        @namespace = ns,
        enclosing_type = parent,
        nested = parent is not null,
        serializable_flag = (def.Attributes & TypeAttributes.Serializable) != 0,
        custom_attributes = def.GetCustomAttributes()
            .Select(AttributeTypeName)
            .Distinct()
            .OrderBy(x => x)
            .ToArray(),
        field_count = fields.Count,
        fields,
    });
}

var doc = new
{
    schema = 2,
    assembly = Path.GetFileName(args[0]),
    type_count = rows.Count,
    types = rows,
};
var options = new JsonSerializerOptions { WriteIndented = true };
File.WriteAllText(args[1], JsonSerializer.Serialize(doc, options) + Environment.NewLine);
return 0;

sealed class TypeNameProvider : ISignatureTypeProvider<string, object?>
{
    private readonly MetadataReader _reader;
    private readonly Func<TypeDefinitionHandle, string> _defName;
    private readonly Func<TypeReferenceHandle, string> _refName;

    public TypeNameProvider(
        MetadataReader reader,
        Func<TypeDefinitionHandle, string> defName,
        Func<TypeReferenceHandle, string> refName)
    {
        _reader = reader;
        _defName = defName;
        _refName = refName;
    }

    public string GetArrayType(string elementType, ArrayShape shape) =>
        elementType + "[" + new string(',', Math.Max(0, shape.Rank - 1)) + "]";
    public string GetByReferenceType(string elementType) => elementType + "&";
    public string GetFunctionPointerType(MethodSignature<string> signature) => "fnptr";
    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) =>
        genericType + "<" + string.Join(", ", typeArguments) + ">";
    public string GetGenericMethodParameter(object? genericContext, int index) => "!!" + index;
    public string GetGenericTypeParameter(object? genericContext, int index) => "!" + index;
    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;
    public string GetPinnedType(string elementType) => elementType;
    public string GetPointerType(string elementType) => elementType + "*";
    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode switch
    {
        PrimitiveTypeCode.Boolean => "bool",
        PrimitiveTypeCode.Byte => "byte",
        PrimitiveTypeCode.SByte => "sbyte",
        PrimitiveTypeCode.Char => "char",
        PrimitiveTypeCode.Int16 => "short",
        PrimitiveTypeCode.UInt16 => "ushort",
        PrimitiveTypeCode.Int32 => "int",
        PrimitiveTypeCode.UInt32 => "uint",
        PrimitiveTypeCode.Int64 => "long",
        PrimitiveTypeCode.UInt64 => "ulong",
        PrimitiveTypeCode.Single => "float",
        PrimitiveTypeCode.Double => "double",
        PrimitiveTypeCode.String => "string",
        PrimitiveTypeCode.Object => "object",
        PrimitiveTypeCode.IntPtr => "IntPtr",
        PrimitiveTypeCode.UIntPtr => "UIntPtr",
        PrimitiveTypeCode.Void => "void",
        _ => typeCode.ToString(),
    };
    public string GetSZArrayType(string elementType) => elementType + "[]";
    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) =>
        _defName(handle);
    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) =>
        _refName(handle);
    public string GetTypeFromSpecification(
        MetadataReader reader,
        object? genericContext,
        TypeSpecificationHandle handle,
        byte rawTypeKind) =>
        reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
}
