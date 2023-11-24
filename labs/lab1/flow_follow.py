from __future__ import annotations


class Pattern:
    """
    Represents a vulnerability pattern, including all its components.
    """

    def __init__(self, name: str, sources: list[str], sanitizers: list[str],
                 sinks: list[str]):
        self.name = name
        self.sources = sources
        self.sanitizers = sources
        self.sinks = sources

    def __repr__(self) -> str:
        return f"Pattern[{name}] {{ sources={sources}, sanitizers={sanitizers}, sinks={sinks} }}"

    def get_sources(self) -> list[str]:
        return self.sources

    def get_sanitizers(self) -> list[str]:
        return self.sanitizers

    def get_sinks(self) -> list[str]:
        return self.sinks

    def is_source(self, name: str) -> bool:
        return name in sources

    def is_sanitizer(self, name: str) -> bool:
        return name in sanitizers

    def is_sink(self, name: str) -> bool:
        return name in sinks


class Label:
    """
    Represents the integrity of information that is carried by a resource.
    Captures the sources that might have influenced a certain piece
    of information, and which sanitizers might have intercepted the
    information since its flow from each source.
    """

    def __init__(self,
                 contents: dict[str, list[str]] = {},
                 sources: list[str] = []):
        # Maps sanitizers to sources it was applied to
        self.contents = contents
        self.sources = sources

    def add_source(self, source: str):
        self.sources.append(source)

    def add_sources(self, sources: list[str]):
        for s in sources:
            self.add_source(source)

    def add_sanitizer(self, sanitizer: str):
        # Sanitizer sanitizes all existing sources
        self.contents[sanitizer] = self.sources.copy()

    def add_sanitizers(self, sanitizers: list[str]):
        for s in sanitizers:
            self.add_sanitizer(s)

    def get_sources(self) -> list[str]:
        return self.sources

    def get_sanitizers(self) -> list[str]:
        return list(self.contents.keys())

    def __add__(self, other: Self) -> Self:
        return self.combine(other)

    def combine(self, other: Self) -> Self:
        # Concatenate contents (creating copies of the lists)
        c = {}
        for s in self.contents:
            c[s] = self.contents[s].copy()

        for s in other.contents:
            if s not in c: c[s] = []
            c[s] += other.contents[s].copy()

        return Label(c, self.get_sources().copy() + other.get_sources.copy())


class Multilabel:
    """
    Generalizes the `Label` class in order to be able to represent distinct
    labels corresponding to different patterns. Represents the product of 
    different label policies (i.e. a vector of labels)
    """

    def __init__(self, labels=[]):
        self.labels = labels

    def get_labels(self):
        return self.labels

    # FIXME: probably add more selectors

    def combine(self, other: Multilabel) -> Multilabel:
        """
        Point wise combination of multilabels - requires multilabels to be 
        compatible (i.e. to be vector of labels of the same size)
        """

        if len(self.labels) != len(other.labels):
            raise ValueError(
                "Multilabel.combine: can't combine incompatible multilabels")

        return Multilabel([
            self.labels[i].combine(other.labels[i])
            for i in range(len(self.labels))
        ])
