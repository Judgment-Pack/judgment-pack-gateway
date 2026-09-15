"""Writes vectors.json: the shared vectors for display policy 1 and schema
grammar 1 (docs/design/tool-descriptors.md).

Every expectation here is written by hand, from the design note; nothing is
computed by running an implementation. The script exists to build the
vectors whose texts are too long to write by hand -- the location, nesting
and member-count limits -- and to say how they were built. Every character
outside printable ASCII is written with chr(), so this file is ASCII and a
reader sees each one. Edit this file, then run it: python3 make_vectors.py
"""
import json

POLICY_REFUSED = [
    # General_Category=Cc, but tab and line feed
    ("U+0000", "Cc"), ("U+0008", "Cc"), ("U+000B", "Cc"), ("U+000D", "Cc"), ("U+001B", "Cc"),
    ("U+007F", "Cc"), ("U+0085", "Cc"), ("U+009F", "Cc"),
    # Bidi_Control
    ("U+061C", "Bidi_Control"), ("U+200E", "Bidi_Control"), ("U+200F", "Bidi_Control"),
    ("U+202A", "Bidi_Control"), ("U+202E", "Bidi_Control"), ("U+2066", "Bidi_Control"), ("U+2069", "Bidi_Control"),
    # Default_Ignorable_Code_Point
    ("U+00AD", "Default_Ignorable_Code_Point"), ("U+034F", "Default_Ignorable_Code_Point"),
    ("U+115F", "Default_Ignorable_Code_Point"), ("U+1160", "Default_Ignorable_Code_Point"),
    ("U+17B4", "Default_Ignorable_Code_Point"), ("U+180B", "Default_Ignorable_Code_Point"),
    ("U+180F", "Default_Ignorable_Code_Point"), ("U+200B", "Default_Ignorable_Code_Point"),
    ("U+200D", "Default_Ignorable_Code_Point"), ("U+2060", "Default_Ignorable_Code_Point"),
    ("U+206F", "Default_Ignorable_Code_Point"), ("U+3164", "Default_Ignorable_Code_Point"),
    ("U+FE00", "Default_Ignorable_Code_Point"), ("U+FE0F", "Default_Ignorable_Code_Point"),
    ("U+FEFF", "Default_Ignorable_Code_Point"), ("U+FFA0", "Default_Ignorable_Code_Point"),
    ("U+1BCA0", "Default_Ignorable_Code_Point"), ("U+1D173", "Default_Ignorable_Code_Point"),
    ("U+E0000", "Default_Ignorable_Code_Point"), ("U+E0001", "Default_Ignorable_Code_Point"),
    ("U+E0041", "Default_Ignorable_Code_Point"), ("U+E0FFF", "Default_Ignorable_Code_Point"),
    # General_Category=Co
    ("U+E000", "Co"), ("U+F8FF", "Co"), ("U+F0000", "Co"), ("U+10FFFD", "Co"),
    # General_Category=Cn, unassigned in Unicode 15.0.0: U+2FFC, U+31EF and
    # U+2EBF0 were assigned in 15.1, so a table from a later version admits
    # them and fails here.
    ("U+0378", "Cn"), ("U+2FFC", "Cn"), ("U+31EF", "Cn"), ("U+2EBF0", "Cn"), ("U+E0080", "Cn"),
    # Noncharacter_Code_Point
    ("U+FDD0", "Noncharacter_Code_Point"), ("U+FDEF", "Noncharacter_Code_Point"),
    ("U+FFFE", "Noncharacter_Code_Point"), ("U+FFFF", "Noncharacter_Code_Point"),
    ("U+1FFFE", "Noncharacter_Code_Point"), ("U+10FFFF", "Noncharacter_Code_Point"),
]

POLICY_ADMITTED = [
    ("U+0009", "tab"), ("U+000A", "line feed"), ("U+0020", "space"), ("U+0041", "letter"),
    ("U+00A0", "no-break space, Zs"), ("U+00E9", "letter"), ("U+2028", "line separator, Zl"),
    ("U+2029", "paragraph separator, Zp"), ("U+3000", "ideographic space"), ("U+1F600", "emoji"),
    ("U+FFFD", "replacement character, So"),
    ("U+FFF9", "Cf, but not Default_Ignorable_Code_Point"),
    ("U+13430", "Cf, but not Default_Ignorable_Code_Point"),
    ("U+0600", "Cf and Prepended_Concatenation_Mark, so not Default_Ignorable_Code_Point"),
    ("U+2FFB", "assigned in 15.0.0"), ("U+1FAF8", "assigned in 15.0.0"),
]

TAB, LF, CR, ESC, NUL = chr(9), chr(10), chr(13), chr(0x1B), chr(0)
E_ACUTE = chr(0xE9)
RLO = chr(0x202E)


def text(schema):
    return json.dumps(schema, separators=(",", ":"), ensure_ascii=False)


def obj(**members):
    return {"type": "object", **members}


def prop(name, schema):
    return obj(properties={name: schema})


def accept(name, schema_text, **extra):
    return {"name": name, "text": schema_text, **extra, "refusal": None}


def refuse(name, schema_text, code, pointer=None, **extra):
    refusal = {"code": code}
    if pointer is not None:
        refusal["pointer"] = pointer
    return {"name": name, "text": schema_text, **extra, "refusal": refusal}


def chain(depth):
    """A root and schema locations nested under it, depth deep in all."""
    inner = {}
    for _ in range(depth - 2):
        inner = {"items": inner}
    return obj(additionalProperties=inner)


def tree(locations):
    """A root, 16 anyOf branches, 16 under each, and the rest spread under
    those, to exactly the number of schema locations given."""
    rest = locations - 1 - 16 - 256
    per, extra = divmod(rest, 256)
    grandchildren = [{"anyOf": [{}] * (per + (1 if i < extra else 0))} for i in range(256)]
    children = [{"anyOf": grandchildren[i * 16:(i + 1) * 16]} for i in range(16)]
    return obj(anyOf=children)


EVERY_KEYWORD = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "title": "Every keyword",
    "description": "Each keyword of the grammar, once or more",
    "$comment": "held to grammar 1",
    "additionalProperties": False,
    "required": ["a"],
    "minProperties": 0,
    "maxProperties": 9007199254740991,
    "properties": {
        "a": {"type": ["string", "null"], "minLength": 0, "maxLength": 80, "examples": ["x", None],
              "default": None, "deprecated": True, "readOnly": False, "writeOnly": False},
        "b": {"type": "number", "exclusiveMinimum": -1.5e308, "exclusiveMaximum": 1e308, "multipleOf": 0.25,
              "minimum": -10, "maximum": 10},
        "c": {"enum": ["x", 1, 1.5, True, None]},
        "d": {"const": "k"},
        "e": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 3},
        "f": {"type": "object", "additionalProperties": {"type": "integer"}, "minProperties": 1},
        "g": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "h": {"oneOf": [{"const": 1}, {"const": 2}]},
        "i": {"allOf": [{"type": "integer"}, {"minimum": 0}]},
        "j": {"not": {"type": "null"}},
        "k": {"default": {"nested": [1, "two", {"three": 3}]}},
    },
}

SCHEMAS = [
    # What is accepted.
    accept("the smallest schema", '{"type":"object"}'),
    accept("a typical tool's arguments",
           text(obj(properties={"query": {"type": "string", "description": "Search text"},
                                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 10}},
                    required=["query"]))),
    accept("every keyword of the grammar", text(EVERY_KEYWORD)),
    accept("the draft-07 dialect",
           '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","additionalProperties":false}'),
    accept("a boolean additionalProperties", '{"type":"object","additionalProperties":true}'),
    accept("whitespace and escapes as the server wrote them",
           '{ "type" : "object" ,' + LF + '  "properties" : { "caf\\u00e9" : { "type" : "string" } } }'),
    accept("names that are keywords elsewhere",
           text(obj(properties={"description": {"type": "string"}, "$ref": {"type": "string"},
                                "format": {"type": "string"}, "properties": {"type": "object"}}))),
    accept("tab and line feed in a description", text(prop("x", {"description": "one" + TAB + "two" + LF + "three"}))),
    accept("a line separator, a no-break space and an emoji",
           text(prop("x", {"title": "a" + chr(0x2028) + "b" + chr(0xA0) + "c " + chr(0x1F600)}))),
    accept("schema locations nested 32 deep", text(chain(32))),
    accept("2048 schema locations", text(tree(2048))),
    accept("a text of 16384 bytes", '{"type":"object"}', padTo=16384),
    accept("a property name of 128 bytes", text(prop("n" * 128, {}))),
    accept("a property name of 128 bytes in 64 characters", text(prop(E_ACUTE * 64, {}))),
    accept("a string of 1024 bytes", text(prop("x", {"description": "d" * 1024}))),
    accept("256 properties", text(obj(properties={"p%03d" % i: {} for i in range(256)}))),
    accept("256 required names", text(obj(required=["r%03d" % i for i in range(256)]))),
    accept("an enum of 256", text(prop("x", {"enum": list(range(256))}))),
    accept("16 branches", text(prop("x", {"anyOf": [{"const": i} for i in range(16)]}))),
    accept("a number of 32 characters", '{"type":"object","properties":{"x":{"default":0.100000000000000000000000000001}}}'),
    accept("exponents at 308", '{"type":"object","properties":{"x":{"minimum":-1e308,"maximum":1E+0308,"multipleOf":1e-308}}}'),
    accept("the largest length", text(prop("x", {"maxLength": 9007199254740991}))),
    accept("an empty property name", '{"type":"object","properties":{"":{"type":"string"}},"required":[""]}'),
    accept("an empty member name in data", '{"type":"object","properties":{"x":{"default":{"":{"":1}}}}}'),

    # A text that is not one strict JSON value.
    refuse("a member name twice", '{"type":"object","type":"object"}', "json"),
    refuse("a lone surrogate", '{"type":"object","title":"\\ud800"}', "json"),
    refuse("trailing content", '{"type":"object"} {}', "json"),

    # The root.
    refuse("a root that is an array", "[]", "not-object", ""),
    refuse("a root that is a boolean", "true", "not-object", ""),
    refuse("a root without type", '{"properties":{}}', "value", "/type"),
    refuse("a root of another type", '{"type":"string"}', "value", "/type"),
    refuse("a root typed by an array", '{"type":["object"]}', "value", "/type"),

    # Keywords outside the grammar.
    refuse("format", text(prop("e", {"type": "string", "format": "email"})), "keyword", "/properties/e/format"),
    refuse("pattern", text(prop("e", {"type": "string", "pattern": "^a"})), "keyword", "/properties/e/pattern"),
    refuse("a reference", text(prop("x", {"$ref": "#/$defs/x"})), "keyword", "/properties/x/$ref"),
    refuse("definitions at the root", text(obj(**{"$defs": {"x": {}}})), "keyword", "/$defs"),
    refuse("the older definitions", text(obj(definitions={"x": {}})), "keyword", "/definitions"),
    refuse("an identifier", text(obj(**{"$id": "https://example.com/s"})), "keyword", "/$id"),
    refuse("an anchor", text(prop("x", {"$anchor": "x"})), "keyword", "/properties/x/$anchor"),
    refuse("a dynamic reference", text(prop("x", {"$dynamicRef": "#x"})), "keyword", "/properties/x/$dynamicRef"),
    refuse("a recursive reference", text(prop("x", {"$recursiveRef": "#"})), "keyword", "/properties/x/$recursiveRef"),
    refuse("patternProperties", text(obj(patternProperties={"^a": {}})), "keyword", "/patternProperties"),
    refuse("propertyNames", text(obj(propertyNames={"maxLength": 3})), "keyword", "/propertyNames"),
    refuse("uniqueItems", text(prop("x", {"type": "array", "uniqueItems": True})), "keyword", "/properties/x/uniqueItems"),
    refuse("a conditional", text(prop("x", {"if": {"type": "string"}})), "keyword", "/properties/x/if"),
    refuse("a keyword no dialect names", text(prop("x", {"x-order": 1})), "keyword", "/properties/x/x-order"),
    refuse("$schema below the root", text(prop("x", {"$schema": "https://json-schema.org/draft/2020-12/schema"})),
           "keyword", "/properties/x/$schema"),
    refuse("a keyword named with ~ and /", text(prop("x", {"a~b/c": 1})), "keyword", "/properties/x/a~0b~1c"),

    # Values not of their keyword's form.
    refuse("draft-04's $schema", '{"$schema":"http://json-schema.org/draft-04/schema#","type":"object"}', "value", "/$schema"),
    refuse("a boolean schema as a property", text(prop("x", True)), "not-object", "/properties/x"),
    refuse("a boolean items", text(prop("x", {"items": False})), "not-object", "/properties/x/items"),
    refuse("the array form of items", text(prop("x", {"items": [{}]})), "value", "/properties/x/items"),
    refuse("a boolean not", text(prop("x", {"not": False})), "not-object", "/properties/x/not"),
    refuse("a boolean branch", text(prop("x", {"anyOf": [True]})), "not-object", "/properties/x/anyOf/0"),
    refuse("no branches", text(prop("x", {"oneOf": []})), "value", "/properties/x/oneOf"),
    refuse("17 branches", text(prop("x", {"allOf": [{} for _ in range(17)]})), "value", "/properties/x/allOf"),
    refuse("a type no dialect names", text(prop("x", {"type": "float"})), "value", "/properties/x/type"),
    refuse("no types", text(prop("x", {"type": []})), "value", "/properties/x/type"),
    refuse("a type twice", text(prop("x", {"type": ["string", "string"]})), "value", "/properties/x/type/1"),
    refuse("a type that is not a name", text(prop("x", {"type": [1]})), "value", "/properties/x/type/0"),
    refuse("properties that are not an object", text(obj(properties=[])), "value", "/properties"),
    refuse("257 properties", text(obj(properties={"p%03d" % i: {} for i in range(257)})), "value", "/properties"),
    refuse("required that is not an array", text(obj(required="a")), "value", "/required"),
    refuse("required that is not a string", text(obj(required=[1])), "value", "/required/0"),
    refuse("a required name twice", text(obj(required=["a", "a"])), "value", "/required/1"),
    refuse("257 required names", text(obj(required=["r%03d" % i for i in range(257)])), "value", "/required"),
    refuse("an empty enum", text(prop("x", {"enum": []})), "value", "/properties/x/enum"),
    refuse("an enum of an array", text(prop("x", {"enum": [[1]]})), "value", "/properties/x/enum/0"),
    refuse("an enum with one number twice", '{"type":"object","properties":{"x":{"enum":[1,1.0]}}}', "value", "/properties/x/enum/1"),
    refuse("an enum with zero twice", '{"type":"object","properties":{"x":{"enum":[0,-0]}}}', "value", "/properties/x/enum/1"),
    refuse("an enum with one string twice", text(prop("x", {"enum": ["a", "a"]})), "value", "/properties/x/enum/1"),
    refuse("an enum of 257", text(prop("x", {"enum": list(range(257))})), "value", "/properties/x/enum"),
    refuse("a constant object", text(prop("x", {"const": {}})), "value", "/properties/x/const"),
    refuse("a minimum written as a string", text(prop("x", {"minimum": "1"})), "value", "/properties/x/minimum"),
    refuse("draft-04's boolean exclusiveMinimum", text(prop("x", {"minimum": 1, "exclusiveMinimum": True})),
           "value", "/properties/x/exclusiveMinimum"),
    refuse("multipleOf zero", text(prop("x", {"multipleOf": 0})), "value", "/properties/x/multipleOf"),
    refuse("multipleOf zero with a fraction", '{"type":"object","properties":{"x":{"multipleOf":0.0e5}}}', "value", "/properties/x/multipleOf"),
    refuse("a negative multipleOf", text(prop("x", {"multipleOf": -2})), "value", "/properties/x/multipleOf"),
    refuse("a length with a fraction", '{"type":"object","properties":{"x":{"minLength":1.0}}}', "value", "/properties/x/minLength"),
    refuse("a length with an exponent", '{"type":"object","properties":{"x":{"maxItems":1e2}}}', "value", "/properties/x/maxItems"),
    refuse("a negative length", text(prop("x", {"minItems": -1})), "value", "/properties/x/minItems"),
    refuse("a length past 2^53-1", text(prop("x", {"maxLength": 9007199254740992})), "value", "/properties/x/maxLength"),
    refuse("a description that is not a string", text(prop("x", {"description": 1})), "value", "/properties/x/description"),
    refuse("a null title", text(prop("x", {"title": None})), "value", "/properties/x/title"),
    refuse("examples that are not an array", text(prop("x", {"examples": {}})), "value", "/properties/x/examples"),
    refuse("deprecated that is not a boolean", text(prop("x", {"deprecated": "yes"})), "value", "/properties/x/deprecated"),

    # Numbers as written.
    refuse("a number of 33 characters", '{"type":"object","properties":{"x":{"default":0.1000000000000000000000000000001}}}',
           "number", "/properties/x/default"),
    refuse("an exponent of 309", '{"type":"object","properties":{"x":{"maximum":1e309}}}', "number", "/properties/x/maximum"),
    refuse("an exponent of -309", '{"type":"object","properties":{"x":{"examples":[1E-309]}}}', "number", "/properties/x/examples/0"),
    refuse("a number in data, far down", '{"type":"object","properties":{"x":{"default":{"a":[{"b":1e999}]}}}}',
           "number", "/properties/x/default/a/0/b"),

    # The limits.
    refuse("schema locations nested 33 deep", text(chain(33)), "nesting", "/additionalProperties" + "/items" * 31),
    refuse("2049 schema locations", text(tree(2049)), "locations"),
    refuse("a text of 16385 bytes", '{"type":"object"}', "text-size", padTo=16385),
    refuse("a property name of 129 bytes", text(prop("n" * 129, {})), "name-size", "/properties/" + "n" * 129),
    refuse("a property name of 130 bytes in 65 characters", text(prop(E_ACUTE * 65, {})), "name-size", "/properties/" + E_ACUTE * 65),
    refuse("a string of 1025 bytes", text(prop("x", {"description": "d" * 1025})), "string-size", "/properties/x/description"),
    refuse("a member name in data of 1025 bytes", text(prop("x", {"default": {"k" * 1025: 1}})), "string-size",
           "/properties/x/default/" + "k" * 1025),

    # Display policy 1, wherever a string is.
    refuse("a right-to-left override in a property name", text(prop("a" + RLO + "b", {})), "policy", "/properties/a" + RLO + "b"),
    refuse("the same, written as an escape", '{"type":"object","properties":{"a\\u202eb":{}}}', "policy", "/properties/a" + RLO + "b"),
    refuse("a zero-width space in a description", text(prop("x", {"description": "a" + chr(0x200B) + "b"})), "policy", "/properties/x/description"),
    refuse("a null in an enum", text(prop("x", {"enum": ["a" + NUL]})), "policy", "/properties/x/enum/0"),
    refuse("private use in a default", text(prop("x", {"default": chr(0xE000)})), "policy", "/properties/x/default"),
    refuse("unassigned in a title", text(prop("x", {"title": chr(0x378)})), "policy", "/properties/x/title"),
    refuse("a noncharacter in an example", text(prop("x", {"examples": [chr(0xFFFE)]})), "policy", "/properties/x/examples/0"),
    refuse("an Arabic letter mark in a comment", text(prop("x", {"$comment": chr(0x61C)})), "policy", "/properties/x/$comment"),
    refuse("a soft hyphen in a required name", text(obj(required=["a" + chr(0xAD) + "b"])), "policy", "/required/0"),
    refuse("a tag character in a constant", text(prop("x", {"const": chr(0xE0041)})), "policy", "/properties/x/const"),
    refuse("a carriage return in a member name in data", text(prop("x", {"default": {"a" + CR + "b": 1}})), "policy",
           "/properties/x/default/a" + CR + "b"),
]

DESCRIPTIONS = [
    {"name": "plain words", "value": "Search tickets by text", "refusal": None},
    {"name": "tab and line feed", "value": "one" + TAB + "two" + LF + "three", "refusal": None},
    {"name": "4096 bytes", "value": "a" * 4096, "refusal": None},
    {"name": "4097 bytes", "value": "a" * 4097, "refusal": "string-size"},
    {"name": "2048 characters of 2 bytes", "value": E_ACUTE * 2048, "refusal": None},
    {"name": "2049 characters of 2 bytes", "value": E_ACUTE * 2049, "refusal": "string-size"},
    {"name": "an emoji sequence joined", "value": chr(0x1F469) + chr(0x200D) + chr(0x1F4BB), "refusal": "policy"},
    {"name": "an emoji with a variation selector", "value": chr(0x2764) + chr(0xFE0F), "refusal": "policy"},
    {"name": "an escape", "value": "red " + ESC + "[31m", "refusal": "policy"},
    {"name": "a bidi isolate", "value": "a" + chr(0x2066) + "b" + chr(0x2069), "refusal": "policy"},
    {"name": "a line separator", "value": "a" + chr(0x2028) + "b", "refusal": None},
]

IDENTITIES = [
    {"name": "a name and a version", "server": {"name": "tickets-mcp", "version": "2.4.1"}, "refusal": None},
    {"name": "an empty version", "server": {"name": "tickets-mcp", "version": ""}, "refusal": None},
    {"name": "a name of 256 bytes", "server": {"name": "n" * 256, "version": "1"}, "refusal": None},
    {"name": "a name of 257 bytes", "server": {"name": "n" * 257, "version": "1"}, "refusal": "string-size"},
    {"name": "a version of 257 bytes", "server": {"name": "s", "version": "v" * 257}, "refusal": "string-size"},
    {"name": "a line feed in the name", "server": {"name": "a" + LF + "b", "version": "1"}, "refusal": None},
    {"name": "an override in the version", "server": {"name": "s", "version": "1" + RLO}, "refusal": "policy"},
]

vectors = {
    "about": [
        "Shared vectors for display policy 1 and schema grammar 1 of docs/design/tool-descriptors.md.",
        "The adapter's capture and the frontend's start each answer to them, with an implementation of its own.",
        "Written by make_vectors.py, whose expectations are written by hand; edit it, not this file.",
        "A schema's text is the candidate's original bytes, as a JSON string here. padTo: spaces are inserted",
        "before the text's last byte until it is that many bytes long.",
        "A refusal names its code and, when it is located, the JSON Pointer of what is refused; a refusal",
        "without a pointer is of the candidate as a whole. Each refused vector breaks exactly one rule.",
        "Secret screening needs the credentials, which the frontend never holds, and is not here.",
    ],
    "displayPolicy": {
        "unicode": "15.0.0",
        "refused": [{"codePoint": cp, "class": cls} for cp, cls in POLICY_REFUSED],
        "admitted": [{"codePoint": cp, "note": note} for cp, note in POLICY_ADMITTED],
    },
    "descriptions": DESCRIPTIONS,
    "identities": IDENTITIES,
    "schemas": SCHEMAS,
}

with open("vectors.json", "w") as f:
    json.dump(vectors, f, indent=1, ensure_ascii=True)
    f.write("\n")
