from __future__ import annotations


class Pattern:
    """
    Represents a vulnerability pattern, including all its components.
    """

    def __init__(self, name: str, sources: list[str], sanitizers: list[str],
                 sinks: list[str]):
        self.name = name
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks

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

    def clone(self) -> Label:
        """
        Returns deep copy
        """

        return Label(
            {
                san: [src for src in self.contents[san]]
                for san in self.contents
            }, [src for src in self.sources])


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

    def clone(self) -> Multilabel:
        """
        Returns deep copy
        """

        return Multilabel([l.clone() for l in self.labels])


class Policy:
    """
    Represents an information flow policy, that uses a pattern database for
    recognizing illegal information flows.
    """

    def __init__(self, patterns: list[Pattern]):
        self.patterns = patterns

    def get_vulnerabilities(self) -> list[str]:
        """
        Returns the vulnerabilities that are being considered
        """
        return list(map(lambda p: p.name, self.patterns))

    def search_source(self, name: str) -> list[str]:
        """
        Returns the vulnerabilities that have a given name as source
        """
        return list(
            map(lambda p: p.name,
                filter(lambda p: name in p.sources, self.patterns)))

    def search_sanitizer(self, name: str) -> list[str]:
        """
        Returns the vulnerabilities that have a given name as sanitizer
        """
        return list(
            map(lambda p: p.name,
                filter(lambda p: name in p.sanitizers, self.patterns)))

    def search_sink(self, name: str) -> list[str]:
        """
        Returns the vulnerabilities that have a given name as sink
        """
        return list(
            map(lambda p: p.name,
                filter(lambda p: name in p.sinks, self.patterns)))

    def find_illegal(self, sink: str, ml: Multilabel) -> Multilabel:
        """
        Receives the name of a sink and returns which labels of the multilabel fit
        some pattern from the database pattern (i.e. which labels encode,
        according to the known patterns, an illegal information flow).
        A label fits a pattern from the database for a given sink name `A` if the
        label has a source `B` such that there is a pattern with source `B` and sink `A`
        """
        # TODO: Improve user comment

        with_sink = set(self.search_sink(sink))

        bad_labels = []
        # TODO: refactor (just use list functionals)
        for label in ml.get_labels():
            for source in label.sources:
                if len(
                        set(self.search_source(source)).intersection(
                            candidates)):
                    bad_labels.append(label)
                    break

        return Multilabel(bad_labels)


class MultiLabelling:
    """
    Mapping from variable names to list of multilabels
    """

    def __init_(self, mapping: dict[str, list[Multilabel]] = {}):
        this.mapping = mapping

    def mlabel_of(self, variable: str) -> list[Multilabel]:
        """
        Returnsn multilabel assigned to a given name
        """
        if variable in mapping:
            return mapping[variable]
        return []

    def mlabel_add(self, variable: str, ml: Multilable):
        """
        ADd multilabel assigned to a given name
        """
        if variable not in mapping:
            mapping[variable] = []

        mapping[variable].append(ml)

    def clone(self) -> MultiLabelling:
        """
        Returns deep copy
        """

        return MultiLabelling({
            variable: [ml.clone() for ml in self.mapping[variable]]
            for variable in this.mapping
        })

    def combine(self, other: Self) -> Self:
        """
        Returns a new multilabelling where multilabels associated
        to names capture what might have happened if either of the multilabellings
        hold.
        """

        combination = self.clone()
        for variable in other.mapping:
            if variable not in combination.mapping:
                combination.mapping[variable] = []

            for ml in other.mapping[variable]:
                combination.mapping[variable].append(ml.clone())

        return combination


class Vulnerability:
    """
    Collects all the illegal flows that were discovered during the analysis of
    a program slice.
    """

    def __init__(self, illegal_flows: dict[str, Multilabel] = {}):
        self.illegal_flows = illegal_flows  # Maps vulnerability name to illegal flows

    def save(self, name: str, ml: Multilabel):
        """
        Saves multilabel which contains the sources and the sanitizers for the
        patterns for which the name is a sink and the flows are illegal (for
        reporting at the end of the analysis)
        """

        if name in self.illegal_flows:
            # TODO: what to do in this case? can this even happen?
            pass

        self.illegal_flows[name] = ml
