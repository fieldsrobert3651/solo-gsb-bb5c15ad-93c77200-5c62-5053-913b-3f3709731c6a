"""End-to-end tests for ``POST /resolve/avoid-vulnerabilities``.

Every index version hit by an advisory's PEP 440 range is removed from this
request's copy of the index (the per-advisory exclusion sets are unioned),
after which the ordinary resolver runs a full backtracking search over the
remaining candidates.  Excluded locked versions cannot be selected again.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _avoid(**payload):
    response = client.post("/resolve/avoid-vulnerabilities", json=payload)
    return response.status_code, response.json()


# web 3.0 would normally win and pull common>=2.0; excluding it forces web
# 2.0, which needs common<2.0 and pulls the previously unneeded ``extra``.
PACKAGES = {
    "app": {"1.0": {"dependencies": {"web": ""}}},
    "web": {
        "3.0": {"dependencies": {"common": ">=2.0"}},
        "2.0": {"dependencies": {"common": "<2.0", "extra": ""}},
    },
    "common": {"1.5": {}, "2.0": {}},
    "extra": {"1.0": {}},
}


def test_affected_versions_are_excluded_and_safe_versions_remain():
    status, body = _avoid(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": ""},
        advisories=[{"id": "ADV-1", "package": "x", "affected": ">=2.0"}],
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["resolved"] == {"x": "1.0"}
    assert body["attempts"] == 1
    assert body["locks"] == {}
    assert body["allow_prereleases"] is False
    assert body["exclusions"] == [
        {
            "advisory": {"id": "ADV-1", "package": "x", "affected": ">=2.0"},
            "package": "x",
            "excluded_versions": ["2.0"],
        }
    ]


def test_full_backtracking_on_remaining_candidates():
    status, body = _avoid(
        packages=PACKAGES,
        root={"app": ""},
        advisories=[{"id": "ADV-WEB3", "package": "web", "affected": ">=3.0"}],
    )
    assert status == 200
    assert body["status"] == "ok"
    # web 3.0 is gone; the remaining web 2.0 branch is fully re-resolved and
    # drags the previously unnecessary ``extra`` package into the closure.
    assert body["resolved"] == {
        "app": "1.0",
        "common": "1.5",
        "extra": "1.0",
        "web": "2.0",
    }
    edges = {(e["source"], e["target"]) for e in body["dependency_graph"]}
    assert edges == {
        ("<root>", "app"),
        ("app", "web"),
        ("web", "common"),
        ("web", "extra"),
    }
    assert all(
        e["target_version"] == body["resolved"][e["target"]]
        for e in body["dependency_graph"]
    )


def test_backtracking_through_remaining_candidates_can_still_conflict():
    packages = {
        "app": {"1.0": {"dependencies": {"web": ">=2.0", "db": ""}}},
        "web": {
            "3.0": {"dependencies": {"common": ">=2.0"}},
            "2.0": {"dependencies": {"common": "<2.0"}},
        },
        "db": {"1.0": {"dependencies": {"common": "==1.5"}}},
        "common": {"1.5": {}, "2.0": {}},
    }
    # Removing web 2.0 leaves only web 3.0, whose common>=2.0 contradicts db.
    status, body = _avoid(
        packages=packages,
        root={"app": ""},
        advisories=[{"id": "ADV", "package": "web", "affected": "<3.0"}],
    )
    assert status == 409
    assert body["status"] == "conflict"
    terminals = body["conflict"]["terminal_conflicts"]
    assert terminals[0]["package"] == "common"
    # The exclusions report is still carried by the conflict response.
    assert body["exclusions"] == [
        {
            "advisory": {"id": "ADV", "package": "web", "affected": "<3.0"},
            "package": "web",
            "excluded_versions": ["2.0"],
        }
    ]
    assert "resolved" not in body


def test_multiple_advisories_exclusion_sets_are_unioned():
    status, body = _avoid(
        packages={"x": {"1.0": {}, "2.0": {}, "3.0": {}}},
        root={"x": ""},
        advisories=[
            {"id": "A", "package": "x", "affected": ">=2.0"},
            {"id": "B", "package": "x", "affected": ">1.0"},
        ],
    )
    assert status == 200
    assert body["resolved"] == {"x": "1.0"}
    (first, second) = body["exclusions"]
    assert first["advisory"]["id"] == "A"
    assert first["excluded_versions"] == ["3.0", "2.0"]
    assert second["advisory"]["id"] == "B"
    assert second["excluded_versions"] == ["3.0", "2.0"]


def test_union_can_remove_every_version_and_conflict():
    status, body = _avoid(
        packages={"x": {"1.0": {}, "2.0": {}, "3.0": {}}},
        root={"x": ""},
        advisories=[
            {"id": "A", "package": "x", "affected": ">=2.0"},
            {"id": "B", "package": "x", "affected": "==1.0"},
        ],
    )
    assert status == 409
    assert body["status"] == "conflict"
    terminals = body["conflict"]["terminal_conflicts"]
    # The package is still in the reduced index, just with no versions left.
    assert terminals[0]["package"] == "x"
    assert terminals[0]["reason"] == "no-versions"
    assert body["exclusions"][0]["excluded_versions"] == ["3.0", "2.0"]
    assert body["exclusions"][1]["excluded_versions"] == ["1.0"]


def test_empty_affected_specifier_excludes_all_versions():
    status, body = _avoid(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": ""},
        advisories=[{"id": "ALL", "package": "x", "affected": ""}],
    )
    assert status == 409
    assert body["status"] == "conflict"
    assert body["exclusions"][0]["excluded_versions"] == ["2.0", "1.0"]


def test_excluded_lock_cannot_be_selected_back():
    status, body = _avoid(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": ""},
        locks={"x": "2.0"},
        advisories=[{"id": "ADV", "package": "x", "affected": ">=2.0"}],
    )
    assert status == 200
    assert body["status"] == "ok"
    # The pinned 2.0 is excluded from the candidate set and never returns.
    assert body["resolved"] == {"x": "1.0"}
    assert body["locks"] == {"x": "missing-version"}
    assert body["exclusions"][0]["excluded_versions"] == ["2.0"]


def test_unaffected_lock_is_still_applied():
    status, body = _avoid(
        packages={"x": {"1.0": {}, "2.0": {}, "3.0": {}}},
        root={"x": ""},
        locks={"x": "1.0"},
        advisories=[{"id": "ADV", "package": "x", "affected": ">=3.0"}],
    )
    assert status == 200
    assert body["resolved"] == {"x": "1.0"}
    assert body["locks"] == {"x": "applied"}


def test_advisory_for_unknown_package_excludes_nothing():
    status, body = _avoid(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": ""},
        advisories=[{"id": "ADV", "package": "ghost", "affected": ">=1.0"}],
    )
    assert status == 200
    assert body["resolved"] == {"x": "2.0"}
    assert body["exclusions"] == [
        {
            "advisory": {"id": "ADV", "package": "ghost", "affected": ">=1.0"},
            "package": "ghost",
            "excluded_versions": [],
        }
    ]


def test_advisory_package_names_are_canonicalized():
    status, body = _avoid(
        packages={"Foo_Bar": {"1.0.0": {}, "2.0": {}}},
        root={"foo-bar": ""},
        advisories=[{"id": "ADV", "package": "FOO-BAR", "affected": ">=2"}],
    )
    assert status == 200
    assert body["resolved"] == {"foo-bar": "1.0.0"}
    assert body["exclusions"][0]["package"] == "foo-bar"
    assert body["exclusions"][0]["excluded_versions"] == ["2.0"]


def test_prereleases_are_matched_as_affected_even_when_hidden_by_default():
    packages = {"x": {"0.9": {}, "1.0a1": {}, "1.0": {}}}
    status, body = _avoid(
        packages=packages,
        root={"x": ""},
        advisories=[{"id": "ADV", "package": "x", "affected": "==1.0a1"}],
    )
    assert status == 200
    # The hidden pre-release is still recognized as an affected index version.
    assert body["exclusions"][0]["excluded_versions"] == ["1.0a1"]
    assert body["resolved"] == {"x": "1.0"}

    # With pre-releases allowed, excluding the pre-release falls back past it.
    status, body = _avoid(
        packages={"x": {"0.9": {}, "1.0a1": {}}},
        root={"x": ""},
        allow_prereleases=True,
        advisories=[{"id": "ADV", "package": "x", "affected": "==1.0a1"}],
    )
    assert status == 200
    assert body["resolved"] == {"x": "0.9"}
    assert body["allow_prereleases"] is True


def test_marker_env_is_honored_on_the_remaining_candidates():
    packages = {
        "app": {"1.0": {"dependencies": ["dep; python_version < '3.11'"]}},
        "dep": {"1.0": {}, "2.0": {}},
    }
    status, body = _avoid(
        packages=packages,
        root=["app"],
        marker_env={"python_version": "3.10"},
        advisories=[{"id": "ADV", "package": "dep", "affected": ">=2.0"}],
    )
    assert status == 200
    assert body["resolved"] == {"app": "1.0", "dep": "1.0"}

    status, body = _avoid(
        packages=packages,
        root=["app"],
        marker_env={"python_version": "3.11"},
        advisories=[{"id": "ADV", "package": "dep", "affected": ">=2.0"}],
    )
    assert status == 200
    assert body["resolved"] == {"app": "1.0"}


def test_empty_advisory_list_behaves_like_resolve():
    status, body = _avoid(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": ""},
        advisories=[],
    )
    assert status == 200
    assert body["resolved"] == {"x": "2.0"}
    assert body["exclusions"] == []

    status, body = _avoid(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": ""},
    )
    assert status == 200
    assert body["resolved"] == {"x": "2.0"}
    assert body["exclusions"] == []


def _backtracking_chain(depth=3):
    """With p0 3.0 present the solve is trivial; excluding it forces an
    exponential re-search through the chain, exactly like withdrawal."""
    packages = {
        "app": {"1.0": {"dependencies": {"p0": ""}}},
        "p0": {
            "3.0": {},
            "2.0": {"dependencies": {"p1": ""}},
            "1.0": {"dependencies": {"p1": ""}},
        },
    }
    for i in range(1, depth):
        packages[f"p{i}"] = {
            "2.0": {"dependencies": {f"p{i+1}": ""}},
            "1.0": {"dependencies": {f"p{i+1}": ""}},
        }
    packages[f"p{depth}"] = {
        "2.0": {"dependencies": {"missing": ""}},
        "1.0": {"dependencies": {"missing": ""}},
    }
    return packages


def test_max_attempts_is_undetermined_not_conflict():
    status, body = _avoid(
        packages=_backtracking_chain(),
        root={"app": ""},
        max_attempts=1,
        advisories=[{"id": "ADV", "package": "p0", "affected": ">=3.0"}],
    )
    assert status == 409
    assert body["status"] == "undetermined"
    assert body["error"]["code"] == "search_limit_exceeded"
    assert "remaining candidates" in body["error"]["message"]
    assert "resolved" not in body
    # Hitting the limit is not treated as unsatisfiable.
    assert body["conflict"] is not None
    assert body["exclusions"][0]["excluded_versions"] == ["3.0"]


def test_deterministic_results():
    payload = {
        "packages": PACKAGES,
        "root": {"app": ""},
        "advisories": [
            {"id": "ADV-1", "package": "web", "affected": ">=3.0"},
            {"id": "ADV-2", "package": "common", "affected": "==2.0"},
        ],
    }
    results = [
        client.post("/resolve/avoid-vulnerabilities", json=payload).json()
        for _ in range(3)
    ]
    assert all(r == results[0] for r in results)


def test_this_requests_index_is_not_mutated():
    payload = {
        "packages": PACKAGES,
        "root": {"app": ""},
        "advisories": [{"id": "ADV", "package": "web", "affected": ">=3.0"}],
    }
    status, body = _avoid(**payload)
    assert status == 200
    assert body["resolved"]["web"] == "2.0"
    # A later plain /resolve still sees the excluded version.
    followup = client.post(
        "/resolve",
        json={"packages": PACKAGES, "root": {"app": ""}},
    ).json()
    assert followup["resolved"]["web"] == "3.0"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_invalid_affected_specifier_is_an_input_error():
    status, body = _avoid(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        advisories=[{"id": "ADV", "package": "x", "affected": "!!1.0"}],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "ADV" in body["error"]["message"]


def test_advisory_shape_validation():
    base = {"packages": {"x": {"1.0": {}}}, "root": {"x": ""}}
    # Missing advisories entries' fields.
    response = client.post(
        "/resolve/avoid-vulnerabilities",
        json={**base, "advisories": [{"id": "ADV", "package": "x"}]},
    )
    assert response.status_code == 422
    # Wrong types.
    response = client.post(
        "/resolve/avoid-vulnerabilities",
        json={**base, "advisories": [{"id": 1, "package": "x", "affected": ""}]},
    )
    assert response.status_code == 422
    # Unexpected field inside an advisory.
    response = client.post(
        "/resolve/avoid-vulnerabilities",
        json={
            **base,
            "advisories": [
                {"id": "ADV", "package": "x", "affected": "", "extra": 1}
            ],
        },
    )
    assert response.status_code == 422
    # Unexpected top-level field.
    response = client.post(
        "/resolve/avoid-vulnerabilities",
        json={
            **base,
            "advisories": [],
            "extra": 1,
        },
    )
    assert response.status_code == 422


def test_resolve_input_validation_is_reused():
    advisory = [{"id": "ADV", "package": "x", "affected": ">=1.0"}]
    status, body = _avoid(
        packages={"x": {"not-a-version": {}}},
        root={"x": ""},
        advisories=advisory,
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"

    status, body = _avoid(
        packages={"x": {"1.0": {}}},
        root=">>>1",
        advisories=advisory,
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"

    status, body = _avoid(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        locks={"x": "not-a-version"},
        advisories=advisory,
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
