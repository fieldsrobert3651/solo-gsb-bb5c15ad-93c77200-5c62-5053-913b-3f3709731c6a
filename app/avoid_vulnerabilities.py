"""Vulnerability avoidance resolution.

Given the same package index, root requirements, locks and solve options as
``/resolve`` plus a local list of security advisories (each naming a package
and the PEP 440 version range it affects), this module removes every affected
version from *this request's* index and then runs the ordinary resolver on
the remaining candidates.

Semantics
---------
* Advisory package names are canonicalized with the same rules as the index
  itself (``Foo_Bar`` and ``foo-bar`` are the same package); the
  ``affected`` string is parsed as a PEP 440 ``SpecifierSet``.
* For every advisory, each version of the named package present in this
  request's index that falls inside the affected range is removed.  The
  exclusion sets of multiple advisories are unioned: a version excluded by
  any advisory never comes back because another advisory is silent about it.
* Only this request's in-memory index is touched; subsequent requests keep
  seeing the original versions.  A package whose versions are all excluded
  stays in the reduced index with an empty version list, so the solver
  reports "no versions left" rather than "package not found".
* The solver then performs a *full* backtracking search over the remaining
  candidates against the complete dependency constraints — never an
  inference along an old graph — so fallback versions and newly pulled-in
  or dropped transitive packages are recomputed from scratch.
* A locked version that was excluded can never be selected: the lock is
  resolved against the reduced index, where the version no longer exists,
  and is reported as ``missing-version`` exactly like any other
  not-present lock.
* On success the response carries the safe ``resolved`` mapping,
  ``dependency_graph``, lock disposition and, per advisory, the concrete
  index versions that advisory actually excluded.  No solution yields the
  ordinary structured conflict (HTTP 409, ``status: "conflict"``);
  exhausting ``max_attempts`` is reported separately as
  ``status: "undetermined"`` (also 409) and is never treated as a proof of
  unsatisfiability.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from packaging.version import Version

from .audit import Advisory, parse_advisories
from .resolver import (
    PackageIndex,
    RootEntry,
    resolve,
)
from .serialize import conflict_summary


def _advisory_exclusions(
    index: PackageIndex, advisories: Iterable[Advisory]
) -> tuple[dict[str, set[Version]], list[list[Version]]]:
    """Match advisories against the index.

    Returns the unioned ``package -> excluded versions`` map used to build
    the reduced index and, aligned with ``advisories`` in input order, the
    versions each single advisory excludes.  Matching passes
    ``prereleases=True``: whether a published index version is affected is a
    fact about the advisory, independent of this request's pre-release
    policy.
    """
    blocked: dict[str, set[Version]] = {}
    per_advisory: list[list[Version]] = []
    for advisory in advisories:
        excluded = [
            version
            for version, _record in index.versions.get(advisory.package, [])
            if advisory.affected.contains(version, prereleases=True)
        ]
        excluded.sort(reverse=True)
        per_advisory.append(excluded)
        blocked.setdefault(advisory.package, set()).update(excluded)
    return blocked, per_advisory


def _avoided_index(
    index: PackageIndex, blocked: dict[str, set[Version]]
) -> PackageIndex:
    """Copy of the index with every blocked version removed.

    Packages stay in the index even when all their versions are excluded, so
    the solver reports them as "no versions left" instead of "not found".
    """
    reduced = PackageIndex()
    for name, records in index.versions.items():
        blocked_versions = blocked.get(name, frozenset())
        reduced.versions[name] = [
            (version, record)
            for version, record in records
            if version not in blocked_versions
        ]
    return reduced


def _exclusions_view(
    advisories: list[Advisory], per_advisory: list[list[Version]]
) -> list[dict[str, Any]]:
    """Render the per-advisory exclusion report in advisory input order."""
    view: list[dict[str, Any]] = []
    for advisory, excluded in zip(advisories, per_advisory):
        view.append(
            {
                "advisory": {
                    "id": advisory.id,
                    "package": advisory.package,
                    "affected": advisory.affected_text,
                },
                "package": advisory.package,
                "excluded_versions": [str(version) for version in excluded],
            }
        )
    return view


def run_avoid_vulnerabilities(
    index: PackageIndex,
    entries: list[RootEntry],
    locks: dict[str, Version],
    advisories_raw: Iterable[Any],
    *,
    allow_prereleases: bool,
    marker_env: Optional[dict[str, str]],
    max_attempts: int,
) -> tuple[dict[str, Any], int]:
    """Exclude advisory-hit versions, solve the remainder, render the body.

    Returns ``(response_body, http_status)``.  Invalid advisory specifiers
    raise :class:`ResolutionInputError` (mapped to HTTP 400 by the caller).
    """
    advisories = parse_advisories(advisories_raw)
    blocked, per_advisory = _advisory_exclusions(index, advisories)
    exclusions = _exclusions_view(advisories, per_advisory)

    result = resolve(
        _avoided_index(index, blocked),
        [entry.dep for entry in entries],
        locks,
        allow_prereleases=allow_prereleases,
        marker_env=marker_env,
        max_attempts=max_attempts,
    )

    body: dict[str, Any] = {
        "attempts": result.attempts,
        "allow_prereleases": allow_prereleases,
        "exclusions": exclusions,
    }

    if result.status == "ok":
        body["status"] = "ok"
        body["resolved"] = result.chosen
        body["dependency_graph"] = result.edges
        body["locks"] = result.lock_notes
        return body, 200

    body["locks"] = result.lock_notes
    body["conflict"] = conflict_summary(result)
    if result.status == "conflict":
        body["status"] = "conflict"
        return body, 409

    # Search limit: undetermined, not unsatisfiable.
    body["status"] = "undetermined"
    body["error"] = {
        "code": "search_limit_exceeded",
        "message": (
            f"resolution on the remaining candidates exceeded "
            f"{max_attempts} candidate evaluations; a safe resolution may "
            "still exist"
        ),
    }
    return body, 409
