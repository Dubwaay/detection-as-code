"""Format of tests.yml, the test cases next to each rule."""

from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, StringConstraints, model_validator

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class Strict(BaseModel):
    # unknown keys are errors, so a typo fails the test
    model_config = ConfigDict(extra="forbid")


class Dataset(Strict):
    """A public log file, pinned by its hash."""

    url: HttpUrl
    sha256: Sha256
    size: int = Field(gt=0)
    sourcetype: str
    source: str


class Expect(Strict):
    min_results: int | None = Field(default=None, ge=1)
    max_results: int | None = Field(default=None, ge=0)
    fields_present: list[str] = []
    match: dict[str, str] = {}

    @model_validator(mode="after")
    def _has_bound(self) -> "Expect":
        if self.min_results is None and self.max_results is None:
            raise ValueError("set min_results, max_results or both")
        return self


class Case(Strict):
    name: str
    description: str
    datasets: list[Dataset] = Field(min_length=1)
    expect: Expect


class CaseFile(Strict):
    rule_id: UUID
    cases: list[Case] = Field(min_length=1)
