from __future__ import annotations


class Pattern:
    """
    Represents a vulnerability pattern, including all its components.
    """

    def __init__(self, name: str, sources: list[str], sanitizers: list[str],
                 sinks: list[str], implicit: bool):
        self.name = name
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
        self.implicit = implicit

    def __repr__(self) -> str:
        return f"Pattern[{self.name}] {{ sources={self.sources}, sanitizers={self.sanitizers}, sinks={self.sinks}, implicit={self.implicit} }}"

    def get_sources(self) -> list[str]:
        return self.sources

    def get_sanitizers(self) -> list[str]:
        return self.sanitizers

    def get_sinks(self) -> list[str]:
        return self.sinks

    def is_source(self, name: str) -> bool:
        return name in self.sources

    def is_sanitizer(self, name: str) -> bool:
        return name in self.sanitizers

    def is_sink(self, name: str) -> bool:
        return name in self.sinks


class Label:
    """
    Represents the integrity of information that is carried by a resource.
    Captures the sources that might have influenced a certain piece
    of information, and which sanitizers might have intercepted the
    information since its flow from each source.
    """

    def __init__(self, pattern: str, contents: dict[str, list[str]],
                 sources: list[str]):
        # Maps sanitizers to sources it was applied to
        self.contents = contents
        self.sources = sources
        self.pattern = pattern

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

        return Label(self.pattern, c,
                     self.get_sources().copy() + other.get_sources().copy())

    def clone(self) -> Label:
        """
        Returns deep copy
        """

        return Label(self.pattern, {
            san: [src for src in self.contents[san]]
            for san in self.contents
        }, [src for src in self.sources])

    def __repr__(self) -> str:
        return f"Label[{self.pattern}] {{ sources={self.sources}, sanitizers/sources map={self.contents}}}"


class MultiLabel:
    """
    Generalizes the `Label` class in order to be able to represent distinct
    labels corresponding to different patterns. Represents the product of 
    different label policies (i.e. a vector of labels)
    """

    def __init__(self, labels={}):
        # Maps pattern name to labels
        assert (type(labels) == dict)
        self.labels = labels

    def get_labels(self):
        return self.labels

    def get_label(self, pattern: str) -> Label:
        """
        Get label give a pattern name
        """
        if pattern not in self.labels:
            self.labels[pattern] = Label(pattern, {}, [])

        return self.labels[pattern]

    def combine(self, other: MultiLabel) -> MultiLabel:
        """
        Point wise combination of multilabels
        """

        combination = self.clone()

        for pattern in other.labels:
            if pattern not in combination.labels:
                combination.labels[pattern] = Label(pattern, {}, [])

            combination.labels[pattern] = combination.labels[pattern].combine(
                other.labels[pattern])

        return combination

    def clone(self) -> MultiLabel:
        """
        Returns deep copy
        """

        return MultiLabel(
            {name: self.labels[name].clone()
             for name in self.labels})

    def __repr__(self) -> str:
        s = f"MultiLabel {{\n"
        for lbl in self.labels.values():
            s += f"\t{str(lbl)},\n"
        s += f"}}\n"
        return s


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

    def get_vulnerability(self, name: str) -> Pattern:
        return list(filter(lambda p: p.name == name, self.patterns))[0]

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

    def find_illegal(self, sink: str, ml: MultiLabel) -> MultiLabel:
        """
        Receives the name of a sink and returns which labels of the multilabel fit
        some pattern from the database pattern (i.e. which labels encode,
        according to the known patterns, an illegal information flow).
        A label fits a pattern from the database for a given sink name `A` if the
        label has a source `B` such that there is a pattern with source `B` and sink `A`
        """

        with_sink = set(self.search_sink(sink))

        bad_labels = {}
        # TODO: refactor (just use list functionals)
        for label in ml.get_labels().values():
            for source in label.sources:
                if len(
                        set(self.search_source(source)).intersection(
                            with_sink)):
                    bad_labels[label.pattern] = label
                    break

        return MultiLabel(bad_labels)


class MultiLabelling:
    """
    Mapping from variable names to list of multilabels
    """

    def __init__(self, mapping: dict[str, MultiLabel]):
        self.mapping = mapping

    def mlabel_of(self, variable: str) -> MultiLabel:
        """
        Returnsn multilabel assigned to a given name
        """
        if variable in self.mapping:
            return self.mapping[variable]
        return None

    def mlabel_set(self, variable: str, ml: Multilabel):
        """
        Set multilabel of given name to provided value
        """
        self.mapping[variable] = ml

    def mlabel_add(self, variable: str, ml: Multilabel):
        """
        Add multilabel assigned to a given name
        """
        if variable not in mapping:
            self.mapping[variable] = MultiLabel()

        self.mapping[variable].combine(ml)

    def clone(self) -> MultiLabelling:
        """
        Returns deep copy
        """

        return MultiLabelling({
            variable: self.mapping[variable].clone()
            for variable in self.mapping
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

    def __repr__(self) -> str:
        s = f"MultiLabelling {{\n"
        for var in self.mapping:
            s += f"\t{var}: {str(self.mapping[var])},\n"
        s += f"}}\n"
        return s


class Vulnerability:
    """
    Collects all the illegal flows that were discovered during the analysis of
    a program slice.
    """

    def __init__(self, illegal_flows: dict[str, MultiLabel] = {}):
        self.illegal_flows = illegal_flows  # Maps vulnerability name to illegal flows

    def save(self, name: str, ml: MultiLabel):
        """
        Saves multilabel which contains the sources and the sanitizers for the
        patterns for which the name is a sink and the flows are illegal (for
        reporting at the end of the analysis)
        """

        if name in self.illegal_flows:
            # TODO: what to do in this case? can this even happen?
            pass

        self.illegal_flows[name] = ml
