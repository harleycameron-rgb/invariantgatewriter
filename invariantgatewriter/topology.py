"""Declaration identity and local placement assessment, never live admission."""

import hashlib
import unicodedata


SAFE_INTEGER = 2**53 - 1
V2_FIELDS = (
    "schema", "moduleId", "version", "purpose", "inputs", "outputs", "constraints",
    "engineConnections", "syntheticTests", "dependencies", "proposedPlacements",
    "evidence", "extractionMethod", "unresolvedQuestions", "businessRequirements",
)
EXTRA_FIELDS = V2_FIELDS[9:]
EXTRACTION_METHODS = ("explicit-declaration", "package-boundary", "static-interface")


def _exact_dependency_version(version):
    from .public_node import _is_version
    if not version.isascii():
        return False
    core, build_separator, build = version.partition("+")
    if build_separator and (not build or any(not part or any(
            not character.isalnum() and character != "-" for character in part)
            for part in build.split("."))):
        return False
    core, prerelease_separator, prerelease = core.partition("-")
    if not _is_version(core) or any(len(part) > 1 and part[0] == "0" for part in core.split(".")):
        return False
    if prerelease_separator:
        parts = prerelease.split(".")
        if any(not part or any(not character.isalnum() and character != "-" for character in part)
               or part.isdecimal() and len(part) > 1 and part[0] == "0" for part in parts):
            return False
    return True


def _package_name(name):
    from .public_node import _is_name
    if name.startswith("@"):
        parts = name[1:].split("/")
        return (len(parts) == 2 and bool(parts[0]) and parts[0].isascii()
                and all(character.isalnum() or character in "._-" for character in parts[0])
                and _is_name(parts[1]))
    return _is_name(name)


def _safe_text(value):
    return all(unicodedata.category(character) not in ("Cc", "Cf", "Cs", "Zl", "Zp")
               for character in value)


def _safe_reference(reference):
    if (not reference.isascii() or reference.startswith("/")
            or any(not character.isalnum() and character not in "._/-" for character in reference)):
        return False
    parts = reference.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    for part in parts:
        lowered = part.lower()
        if (lowered.startswith((".env", ".git", "credentials", "secrets", "id_rsa", "id_ed25519"))
                or lowered in ("node_modules", "vendor", ".ssh", ".aws", ".azure", ".npmrc", ".netrc",
                               ".pypirc", ".config", "home", "user", "users", "private", "personal",
                               "downloads", "documents", "desktop")
                or lowered.endswith((".pem", ".key", ".p12", ".pfx", ".jpg", ".jpeg", ".png", ".gif",
                                     ".mp4", ".mov", ".mp3", ".wav", ".pdf"))):
            return False
    return parts[-1].lower().split(".")[0] not in ("key", "keys")


def validate_declaration(manifest):
    """Validate v2 and hash its full canonical JSON; errors contain no input data."""
    from .public_node import _bounded, _object, _require, _string, _array, _validate_v1, NAME, _is_name

    canonical = _bounded(manifest)
    _require(type(manifest) is dict
             and set(manifest) in (set(V2_FIELDS) - {"businessRequirements"}, set(V2_FIELDS)),
             "Invalid object fields.")
    _require(manifest["schema"] == "module-manifest/2", "Unsupported manifest schema.")

    def walk(value):
        if type(value) is dict:
            for key, child in value.items():
                _require(_is_name(key), "Invalid object field name.")
                walk(child)
        elif type(value) is list:
            for child in value:
                walk(child)
        elif type(value) is str:
            _require(_safe_text(value), "Unsafe Unicode string.")
        elif type(value) in (int, float):
            _require(type(value) is int and abs(value) <= SAFE_INTEGER,
                     "Version 2 numbers must be JSON safe integers.")

    walk(manifest)
    base = {key: value for key, value in manifest.items() if key not in EXTRA_FIELDS}
    base["schema"] = "module-manifest/1"
    _validate_v1(base)
    requirements = manifest.get("businessRequirements", {
        "function": manifest["purpose"], "inputs": manifest["inputs"],
        "outputs": manifest["outputs"],
        "acceptanceCases": [test["name"] for test in manifest["syntheticTests"]],
    })
    _object(requirements, ("function", "inputs", "outputs", "acceptanceCases"))
    _string(requirements["function"], maximum=4096)
    _require(bool(requirements["function"].strip()), "Business function is required.")
    _require(requirements["inputs"] == manifest["inputs"]
             and requirements["outputs"] == manifest["outputs"],
             "Business requirement ports must match the declared module ports.")
    _array(requirements["acceptanceCases"], 64)
    cases = []
    for case in requirements["acceptanceCases"]:
        _string(case, pattern=NAME)
        _require(case not in cases, "Duplicate business acceptance case.")
        cases.append(case)
    _require(cases == [test["name"] for test in manifest["syntheticTests"]],
             "Business acceptance cases must match the declared synthetic tests.")
    _array(manifest["dependencies"], 32)
    names = set()
    for dependency in manifest["dependencies"]:
        _object(dependency, ("moduleId", "version"))
        _string(dependency["moduleId"], maximum=128)
        _require(_package_name(dependency["moduleId"]) and ".." not in dependency["moduleId"],
                 "Invalid dependency name.")
        _string(dependency["version"], maximum=128)
        _require(dependency["moduleId"] not in names, "Duplicate dependency name.")
        names.add(dependency["moduleId"])
    _array(manifest["proposedPlacements"], 32)
    placements = set()
    for placement in manifest["proposedPlacements"]:
        _string(placement, pattern=NAME)
        _require(placement not in placements, "Duplicate proposed placement.")
        placements.add(placement)
    _array(manifest["evidence"], 32)
    for evidence in manifest["evidence"]:
        _object(evidence, ("reference", "method"))
        _string(evidence["reference"], maximum=512)
        _require(_safe_reference(evidence["reference"]), "Unsafe evidence reference.")
        _string(evidence["method"], maximum=128)
    _require(manifest["extractionMethod"] in EXTRACTION_METHODS, "Invalid extraction method.")
    _array(manifest["unresolvedQuestions"], 32)
    for question in manifest["unresolvedQuestions"]:
        _string(question, maximum=4096)
    for constraint in manifest["constraints"]:
        if constraint["kind"] in ("includeEngine", "excludeEngine"):
            _string(constraint["value"], pattern=NAME)
    return hashlib.sha512(canonical).hexdigest()


def builtin_engine_catalog():
    """Local predefined test implementations, not remote deployment connections."""
    from .public_node import INTERFACES
    return {
        "identity": {"identity/1": INTERFACES["identity/1"]},
        "numbers": {"numbers.add/1": INTERFACES["numbers.add/1"]},
        "text": {"text.concat/1": INTERFACES["text.concat/1"]},
        "boolean": {"boolean.not/1": INTERFACES["boolean.not/1"]},
        "local-sandbox": dict(INTERFACES),
    }


def assess_declaration(manifest, digest, *, test_receipt=None,
                       available_dependencies=None, engine_catalog=None):
    """Narrow the finite candidate set using trusted tests and configuration.

    Configuration and test_receipt are trusted backend inputs, never client
    availability claims. A receipt must come from this node's executed tests.
    """
    from .public_node import _require, _ports, _constraint_findings, INTERFACES
    _require(validate_declaration(manifest) == digest, "Declaration digest mismatch.")
    catalog = builtin_engine_catalog() if engine_catalog is None else engine_catalog
    dependencies = {} if available_dependencies is None else available_dependencies
    proposed = list(manifest["proposedPlacements"])
    feasible = set(proposed or catalog.keys())
    evidence, unresolved = [], []

    def check(kind, reason, *, keep=None, pending=False, details=None):
        before = sorted(feasible)
        if keep is not None:
            feasible.intersection_update(keep)
        record = {"kind": kind, "status": "unresolved" if pending else
                  "incompatible" if keep is not None and not feasible else "resolved",
                  "before": before, "after": sorted(feasible), "reason": reason,
                  "evidence": details or {}}
        evidence.append(record)
        if pending:
            unresolved.append(reason)

    check("availability", "Only backend-configured local engines are available.",
          keep=set(catalog), details={"catalog": sorted(catalog), "scope": "local synthetic implementations"})
    if not proposed:
        check("placements", "No engine placements were explicitly proposed.", pending=True)
    check("identity", "SHA-512 identifies the declaration, not compatibility.",
          details={"moduleId": manifest["moduleId"], "declarationSha512": digest})
    check("extraction", "An explicit declaration is required for a complete assessment.",
          pending=manifest["extractionMethod"] != "explicit-declaration",
          details={"method": manifest["extractionMethod"]})
    for question in manifest["unresolvedQuestions"]:
        check("question", question, pending=True)
    for item in manifest["evidence"]:
        check("declaration-evidence", "Declaration reference is metadata, not verified availability.",
              details=dict(item))
    for connection in manifest["engineConnections"]:
        name = connection["interface"]
        signature = (_ports(connection["inputs"]), _ports(connection["outputs"]))
        signatures = [interfaces[name] for interfaces in catalog.values() if name in interfaces]
        if name in INTERFACES:
            signatures.append(INTERFACES[name])
        details = {"connection": connection["name"], "interface": name,
                   "required": connection["required"], "inputs": signature[0], "outputs": signature[1]}
        if not signatures:
            check("interface", "Interface compatibility is unknown.", pending=True, details=details)
        elif not any(signature == known for known in signatures):
            check("interface", "Declared port signature does not match the known interface.",
                  keep=set(), details=details)
        elif connection["required"]:
            supported = {engine for engine, interfaces in catalog.items()
                         if interfaces.get(name) == signature}
            check("interface", "Required interface narrows local engine choices.",
                  keep=supported, details=details)
        else:
            check("interface", "Optional known interface has a compatible port signature.", details=details)
    findings = iter(_constraint_findings(manifest))
    for constraint in manifest["constraints"]:
        finding = next(findings)
        kind, value = constraint["kind"], constraint["value"]
        if kind in ("includeEngine", "excludeEngine"):
            keep = {value} if kind == "includeEngine" else set(feasible) - {value}
            check("constraint", "Engine inclusion/exclusion narrows placement choices.",
                  keep=keep, details=dict(constraint))
        elif kind in ("maxStringLength", "maxArrayLength", "nonNegativeNumbers"):
            details = dict(finding)
            if kind == "maxArrayLength":
                details["scope"] = "module/connection port lists, engineConnections and syntheticTests only"
            check("constraint", "Structural constraint " + finding["status"] + ".",
                  keep=set() if finding["status"] == "violated" else None,
                  pending=finding["status"] == "unresolved", details=details)
        else:
            check("constraint", "Unsupported constraint remains unresolved.", pending=True,
                  details=dict(constraint))
    for dependency in manifest["dependencies"]:
        name, version = dependency["moduleId"], dependency["version"]
        details = dict(dependency)
        exact = _exact_dependency_version(version)
        if not exact:
            check("dependency", "Dependency version range is not resolved by this backend.",
                  pending=True, details=details)
        elif name not in dependencies:
            check("dependency", "Dependency availability has not been established by the backend.",
                  pending=True, details=details)
        elif dependencies[name] != version:
            check("dependency", "Configured dependency version is incompatible.",
                  keep=set(), details=details)
        else:
            check("dependency", "Exact dependency version is available in backend configuration.",
                  details=details)
    receipt = test_receipt if type(test_receipt) is dict else {}
    tests = receipt.get("tests", [])
    scope = receipt.get("scope", {})
    matching = (receipt.get("schema") == "module-synthetic-receipt/2"
                and receipt.get("declarationSha512") == digest and receipt.get("synthetic") is True
                and receipt.get("signed") is False
                and receipt.get("liveAdmission") is False
                and type(scope) is dict
                and scope.get("execution") == "backend-defined builtin connection interfaces only")
    executed = (matching and type(tests) is list and bool(tests)
                and {test.get("name") for test in tests if type(test) is dict}
                == {test["name"] for test in manifest["syntheticTests"]}
                and len(tests) == len(manifest["syntheticTests"]))
    expected = {test["name"]: test["expectedOutputs"] for test in manifest["syntheticTests"]}
    passed = executed and receipt.get("status") == "passed" and all(
        type(test) is dict and test.get("status") == "passed"
        and type(test.get("actualOutputs")) is dict
        and test["actualOutputs"] == expected[test["name"]]
        and all(type(actual) is type(expected[test["name"]][name])
                for name, actual in test["actualOutputs"].items()) for test in tests)
    failed = executed and (receipt.get("status") == "failed" or any(
        type(test) is dict and test.get("status") == "failed" for test in tests))
    if executed:
        connection_by_name = {connection["name"]: connection
                              for connection in manifest["engineConnections"]}
        results_by_name = {test["name"]: test for test in tests if type(test) is dict}
        for case in manifest["syntheticTests"]:
            result = results_by_name[case["name"]]
            if result.get("status") not in ("passed", "failed"):
                continue
            connection = connection_by_name[case["connection"]]
            interface = connection["interface"]
            signature = (_ports(connection["inputs"]), _ports(connection["outputs"]))
            supported = {engine for engine, interfaces in catalog.items()
                         if interfaces.get(interface) == signature}
            check("acceptance-case",
                  "Passing acceptance evidence narrows compatible local candidates."
                  if result["status"] == "passed" else
                  "Failed acceptance evidence excludes candidates for this interface.",
                  keep=supported if result["status"] == "passed" else set(),
                  details={"case": case["name"], "connection": case["connection"],
                           "moduleId": manifest["moduleId"], "interface": interface,
                           "status": result["status"], "expectedOutputs": case["expectedOutputs"],
                           "actualOutputs": result.get("actualOutputs"),
                           "candidatePlacements": sorted(supported)})
    check("synthetic-tests", "Executed backend synthetic tests passed." if passed else
          "Executed backend synthetic tests failed." if failed else
          "Passing executed backend synthetic tests are still required.",
          keep=set() if failed else None, pending=not passed and not failed,
          details={"status": receipt.get("status", "not_run"),
                   "scope": "builtin connection assertions only; no module or live deployment executed"})
    status = "incompatible" if not feasible else "pending" if unresolved else "complete"
    return {
        "identityRing": {"moduleId": manifest["moduleId"], "declarationSha512": digest},
        "placementRing": {"moduleId": manifest["moduleId"], "proposed": proposed,
                          "feasible": sorted(feasible)},
        "status": status, "evidence": evidence, "unresolvedConditions": unresolved,
        "liveAdmission": False, "assessmentScope": "local synthetic declaration assessment only",
    }
