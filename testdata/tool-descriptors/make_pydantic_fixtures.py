"""Writes pydantic.json: what Pydantic emits for the arguments of a tool --
the MCP Python SDK's FastMCP builds a model from a tool function's
signature and sends model_json_schema() -- with whether schema grammar 1
accepts it, and if not, where it refuses (docs/design/tool-descriptors.md).

Each expectation is written by hand. Run with the Pydantic version named in
GENERATOR, which the file records:

    python3 -m venv /tmp/p && /tmp/p/bin/pip install pydantic==2.11.7
    /tmp/p/bin/python make_pydantic_fixtures.py
"""
import datetime
import enum
import json
import uuid
from typing import Literal, Optional, Union

import pydantic
from pydantic import BaseModel, ConfigDict, Field

GENERATOR = "pydantic 2.11.7"
assert pydantic.VERSION == GENERATOR.split()[1], pydantic.VERSION


class search_ticketsArguments(BaseModel):
    query: str
    limit: int = 10
    include_closed: bool = False


class optionalArguments(BaseModel):
    owner: Optional[str] = None
    tags: list[str] = []
    after: Optional[int] = Field(None, ge=0)


class literalArguments(BaseModel):
    status: Literal["open", "closed"]
    priority: Literal[1, 2, 3] = 2


class constrainedArguments(BaseModel):
    page: int = Field(1, ge=1, le=1000, description="Page number")
    name: str = Field(..., min_length=1, max_length=80, examples=["Ada"])
    ratio: float = Field(0.5, gt=0, lt=1)
    step: float = Field(..., multiple_of=0.25)


class mappingArguments(BaseModel):
    counts: dict[str, int]
    matrix: list[list[float]] = Field(..., min_length=1, max_length=4)


class unionArguments(BaseModel):
    key: Union[int, str]


class strictArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str


class patternArguments(BaseModel):
    code: str = Field(..., pattern=r"^[A-Z]{3}$")


class dateArguments(BaseModel):
    since: datetime.datetime


class uuidArguments(BaseModel):
    id: uuid.UUID


class Address(BaseModel):
    city: str


class nestedArguments(BaseModel):
    address: Address


class Colour(enum.Enum):
    red = "red"
    blue = "blue"


class enumArguments(BaseModel):
    colour: Colour


# (model, the refusal written by hand: None, or (code, pointer))
FIXTURES = [
    (search_ticketsArguments, None),
    (optionalArguments, None),
    (literalArguments, None),
    (constrainedArguments, None),
    (mappingArguments, None),
    (unionArguments, None),
    (strictArguments, None),
    (patternArguments, ("keyword", "/properties/code/pattern")),
    (dateArguments, ("keyword", "/properties/since/format")),
    (uuidArguments, ("keyword", "/properties/id/format")),
    # A nested model is a reference to a definition: $defs sorts first.
    (nestedArguments, ("keyword", "/$defs")),
    (enumArguments, ("keyword", "/$defs")),
]

out = {
    "about": [
        "Input schemas as Pydantic emits them for a tool's arguments, each written as the MCP Python SDK",
        "sends it, compact. Written by make_pydantic_fixtures.py, whose expectations are written by hand.",
    ],
    "generator": GENERATOR,
    "fixtures": [],
}
for model, refusal in FIXTURES:
    text = json.dumps(model.model_json_schema(by_alias=True), separators=(",", ":"), ensure_ascii=False)
    entry = {"name": model.__name__, "text": text, "refusal": None}
    if refusal:
        entry["refusal"] = {"code": refusal[0], "pointer": refusal[1]}
    out["fixtures"].append(entry)

with open("pydantic.json", "w") as f:
    json.dump(out, f, indent=1, ensure_ascii=True)
    f.write("\n")
