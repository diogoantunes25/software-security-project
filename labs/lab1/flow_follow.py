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

    def __init__(self, sources=[], sanitizers=[]):
        self.sources = sources
        self.sanitizers = sanitizers

        # FIXME: might be missing something that saves order in which things
        # happened (where tainted source came before or after sanitizer)

    def add_source(self, source: str):
        self.sources.append(source)

    def add_sources(self, sources: list[str]):
        self.sources += sources

    def add_sanitizer(self, sanitizer: str):
        self.sanitizers.append(sanitizer)

    def add_sanitizers(self, sanitizers: list[str]):
        self.sanitizers += sanitizers

    def get_sources(self) -> list[str]:
        return self.sources

    def get_sanitizers(self) -> list[str]:
        return self.sanitizers

    def __add__(self, other: Self) -> Self:
        return self.combine(other)

    def combine(self, other: Self) -> Self:
        return Label(
            self.get_sources().copy() + other.get_sources.copy(),
            self.get_sanitizers().copy() + other.get_sanitizers().copy())


class Multilabel:
    """
    Generalizes the `Label` class in order to be able to represent distinct
    labels corresponding to different patterns.
    """

    def __init__(self, labels=[]):
        self.labels = labels

    def get_labels(self):
        return self.labels

    # FIXME: probably add more selectors

    def combine(self, other: Multilabel) -> Multilabel:
        return Multilabel(self.get_labels().copy() + other.get_labels().copy())
