from __future__ import annotations
import logging, json


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

    def from_json(json: str) -> Pattern:
        return Pattern(
            json["vulnerability"],
            json["sources"],
            json["sanitizers"],
            json["sinks"],
            json["implicit"] == "yes",
        )


class Element:
    """
    Represents a function/variable found at a given line
    """

    def __init__(self, name: str, lineno: int):
        self.name = name
        self.lineno = lineno

    def __repr__(self) -> str:
        return f"{self.name}@{self.lineno}"

    def __eq__(self, other):
        if isinstance(other, Element):
            return self.name == other.name and self.lineno == other.lineno
        return False

    def __hash__(self):
        return hash(self.name) ^ hash(self.lineno)

    def clone(self):
        return Element(self.name, self.lineno)


class Source(Element):

    def __init__(self, name: str, lineno: int):
        super().__init__(name, lineno)

    def __repr__(self) -> str:
        return f"Source({self.name}@{self.lineno})"

    def get_source(self) -> Source:
        return self

    def __hash__(self):
        return hash(self.name) ^ hash(self.lineno)

    def __eq__(self, other):
        if not isinstance(other, Source):
            return False
        return self.name == other.name and self.lineno == other.lineno

    def clone(self):
        return Source(self.name, self.lineno)


class Sanitized(Element):

    def __init__(self, name: str, lineno: int, of: Element):
        super().__init__(name, lineno)
        assert (type(of) == Source or type(of) == Sanitized)

        self.name = name
        self.lineno = lineno

        # Don't do two sanitizers in a row (TODO: What about f, g, f, g ?)
        if name == of.name and lineno == of.lineno:
            self.of = of.of
        else:
            self.of = of

    def __repr__(self) -> str:
        return f"Sanitized({self.name}@{self.lineno} | {self.of})"

    def get_source(self) -> Source:
        return self.of.get_source()

    def __hash__(self):
        return hash(self.name) ^ hash(self.lineno) ^ hash(self.of)

    def __eq__(self, other):
        if not isinstance(other, Sanitized):
            return False
        return self.name == other.name and self.lineno == other.lineno and self.of == other.of

    def clone(self):
        return Sanitized(self.name, self.lineno, self.of.clone())


class Label:
    """
    Represents the integrity of information that is carried by a resource.
    Captures the sources that might have influenced a certain piece
    of information, and which sanitizers might have intercepted the
    information since its flow from each source.
    """

    def __init__(self, pattern: str, values: set[Element]):
        # Maps sanitizers to sources it was applied to
        assert (type(values) == set)
        self.values = values
        self.pattern = pattern

    def __eq__(self, other) -> bool:
        if not isinstance(other, Label):
            return False

        return self.pattern == other.pattern and self.values == other.values

    def add_source(self, source: Source):
        assert (type(source) == Source)
        self.values.add(source)

    def add_sources(self, sources: list[Element]):
        for s in sources:
            self.add_source(source)

    def add_sanitizer(self, sanitizer: Element):
        assert (type(sanitizer) == Element)
        # Sanitizer sanitizes all existing sources
        new = set()
        for val in self.values:
            new_val = Sanitized(sanitizer.name, sanitizer.lineno, val)
            new.add(new_val)

        self.values = new

    def add_sanitizers(self, sanitizers: list[Element]):
        for s in sanitizers:
            self.add_sanitizer(s)

    def combine(self, other: Self) -> Self:
        assert (self.pattern == other.pattern)
        return Label(self.pattern, self.values.union(other.values))

    def clone(self) -> Label:
        """
        Returns deep copy (immutable, not deep copy needed)
        """

        new = set()

        for el in self.values:
            new.add(el.clone())

        return Label(self.pattern, new)

    def __repr__(self) -> str:
        return f"Label[{self.pattern}] {{ {self.values} }}"


class MultiLabel:
    """
    Generalizes the `Label` class in order to be able to represent distinct
    labels corresponding to different patterns. Represents the product of 
    different label policies (i.e. a vector of labels)
    """

    def __init__(self, labels: dict[str, Label]):
        # Maps pattern name to labels
        assert (type(labels) == dict)
        self.labels = labels

    def __eq__(self, other) -> bool:
        if not isinstance(other, MultiLabel):
            return False

        if list(self.labels.keys()) != list(other.labels.keys()):
            return False

        for var in self.labels:
            if self.labels[var] != other.labels[var]:
                return False
        return True

    def get_labels(self):
        return self.labels

    def get_label(self, pattern: str) -> Label:
        """
        Get label give a pattern name
        """
        if pattern not in self.labels:
            self.labels[pattern] = Label(pattern, set())

        return self.labels[pattern]

    def combine(self, other: MultiLabel) -> MultiLabel:
        """
        Point wise combination of multilabels
        """

        combination = self.clone()

        for pattern in other.labels:
            if pattern not in combination.labels:
                combination.labels[pattern] = Label(pattern, set())

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

    def filter_implicit(self, policy: Policy) -> MultiLabel:
        """
        Returns (not deep) copy that does not contain the labels for patterns
        that are marked as not wanting implicit flows by policy
        """
        implicit = policy.get_implicit_vulnerabilities()

        return MultiLabel({
            name: self.labels[name]
            for name in self.labels if name in implicit
        })

    def __repr__(self) -> str:
        s = f"MultiLabel {{ "
        for lbl in self.labels.values():
            s += f"{str(lbl)}, "
        s += f" }}"
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

    def get_implicit_vulnerabilities(self) -> list[str]:
        """
        Returns the vulnerabilities that are being considered and are marked
        as including implicit flows
        """
        return list(
            map(lambda p: p.name, filter(lambda p: p.implicit, self.patterns)))

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

        bad_labels = {}
        for pattern in self.patterns:
            if pattern.is_sink(sink):
                lbl = ml.get_label(pattern.name)
                bad_labels[lbl.pattern] = lbl

        return MultiLabel(bad_labels)

    def __repr__(self) -> str:
        s = f"Policy {{ "
        for p in self.patterns:
            s += f"{str(p)}, "
        s += f" }}"
        return s


class MultiLabelling:
    """
    Mapping from variable names to list of multilabels
    """

    def __init__(self, mapping: dict[str, MultiLabel]):
        self.mapping = mapping

    def __eq__(self, other) -> bool:
        if not isinstance(other, MultiLabelling):
            return False

        if list(self.mapping.keys()) != list(other.mapping.keys()):
            return False

        for var in self.mapping:
            if self.mapping[var] != other.mapping[var]:
                return False
        return True

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

        logging.debug(f"Combining {self} and {other}")

        combination = self.clone()
        for variable in other.mapping:
            if variable not in combination.mapping:
                combination.mapping[variable] = MultiLabel({})

            combination.mapping[variable] = combination.mapping[
                variable].combine(other.mapping[variable].clone())

        return combination

    def __repr__(self) -> str:
        s = f"MultiLabelling {{ "
        for var in self.mapping:
            s += f"{var}: {str(self.mapping[var])}, "
        s += f" }}"
        return s


class Vulnerability:
    """
    Collects all the illegal flows that were discovered during the analysis of
    a program slice.
    """

    def __init__(self, illegal_flows: dict[str, list[MultiLabel]] = {}):
        self.illegal_flows = illegal_flows  # Maps vulnerability name to illegal flows

    def save(self, sink: Element, ml: MultiLabel):
        """
        Saves multilabel which contains the sources and the sanitizers for the
        patterns for which the name is a sink and the flows are illegal (for
        reporting at the end of the analysis)
        """

        if sink not in self.illegal_flows:
            self.illegal_flows[sink] = []

        self.illegal_flows[sink].append(ml)

    def __repr__(self) -> str:
        s = f"Vulnerability {{ "
        for var in self.illegal_flows:
            s += f"{var}: {str(self.illegal_flows[var])}, "
        s += f" }}"
        return s

    def to_json(self) -> str:
        vulns = {}

        for sink in self.illegal_flows:
            flows = self.illegal_flows[sink]
            for mlb in self.illegal_flows[sink]:
                for lbl in mlb.labels.values():
                    for val in lbl.values:
                        src = val.get_source()
                        key = ((src.name, src.lineno),
                               (sink.name, sink.lineno), lbl.pattern)
                        if key not in vulns:
                            vulns[key] = []

                        sanitization = []
                        while type(val) != Source:
                            sanitization.append([val.name, val.lineno])
                            val = val.of

                        vulns[key].append(sanitization)

        ans = []
        count = {}

        for key in vulns:
            traces = vulns[key]
            src, sink, vuln_name = key
            src_name, src_lineno = src
            sink_name, sink_lineno = sink
            d = {}
            if vuln_name not in count:
                count[vuln_name] = 0

            count[vuln_name] += 1
            d["vulnerability"] = f"{vuln_name}_{count[vuln_name]}"
            d["source"] = [src_name, src_lineno]
            d["sink"] = [sink_name, sink_lineno]

            empty = False
            d["sanitized_flows"] = []
            for trace in traces:
                if len(trace) == 0:
                    empty = True
                else:
                    d["sanitized_flows"].append(trace)

            d["unsanitized_flows"] = "yes" if empty else "no"
            ans.append(d)

        return json.dumps(ans, indent=4)
