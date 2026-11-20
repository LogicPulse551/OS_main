"""Explain how a managed IIO caller relates to the checked empty-converter rule."""
import re

from .api_inputs import file_hash
from .sixbyte_scan import _TRIVIA


# These are kernel interface implementations, shared by every analyzed driver.
# A different implementation needs a fresh review of the quoted contracts.
FRAMEWORK = {
    "drivers/base/regmap/regmap.c": ("3d4b622a577f2a008539727d9d26b422112da67dcea170e05ba9d567e2f5a7a9",
        {"format_initialization": [974, 980, 987, 992, 1017, 1022], "publish": [596, 597, 1157],
         "lookup": [1516, 1518, 1523], "reinit_cache": [1421, 1437, 1448],
         "regmap_release": [1187, 1205], "read_window": [3001, 3212, 3214, 3217, 3218]}),
    "drivers/base/devres.c": ("71e9a931b8746a85a0c67c9f2370aace6aa2c1c67e1110cf49e157fb79522d4d",
        {"latest_matching_resource": [285, 290, 299], "reverse_release": [540, 544, 546]}),
    "drivers/iio/industrialio-trigger.c": ("cb8379dafb180288411b608e78fb0332a258700ff845f8c89573f5c601da95b3",
        {"poll_argument": [300, 302, 386, 388], "detach_error": [341, 342, 343, 348],
         "nested_dispatch": [226, 235], "consumer_parent_check": [730, 735]}),
    "kernel/irq/chip.c": ("76e8a4736a39778392aaf60dc91f61d6fd4e12536cbe53e272c1add1a82b9e28",
        {"synchronous_nested_thread": [575, 589, 594, 599]}),
    "kernel/irq/manage.c": ("1e1c274718c9e5982e75e108948779d22ff7c12daca03bc0ce60d10fc954dcdc",
        {"wait_for_physical_irq": [1859, 1935, 1960]}),
    "drivers/spi/spi.c": ("19c129f9ad7e7ebf0fb10e668e1f4e086bf4f1bb3d0a12c6cbaeb5d0fffd2c70",
        {"synchronous_buffer": [4885, 4923, 4924, 4927, 4928, 4929]}),
}


def framework(root):
    evidence = {}
    for relative, (expected, uses) in FRAMEWORK.items():
        path = root / relative
        if path.resolve(strict=True) != path or file_hash(path) != expected:
            raise ValueError("Unreviewed framework contract: " + relative)
        lines = path.read_text(encoding="utf-8").splitlines()
        evidence[relative] = {"sha256": expected, "facts": {
            fact: [{"line": i, "text": lines[i-1].strip()} for i in positions]
            for fact, positions in uses.items()}}
    return evidence


def source_matches(path, pattern):
    source = path.read_bytes().decode("latin1")
    code = _TRIVIA.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), source)
    return [{"line": code.count("\n", 0, m.start()) + 1, "text": m.group().strip()}
            for m in re.finditer(pattern, code)]


def assess(root, site):
    """Report remaining premises. Observations and source matches cannot authorize an emit."""
    result = dict(site)
    if site["count"] is None:
        return dict(result, reason="value_count_unresolved")
    if site["count"] != 6:
        return dict(result, reason="not_six_one_byte_values")
    if not site["owners"] or not site["private_path"]:
        return dict(result, reason="managed_iio_owner_not_established")

    driver = root / site["source"]
    contracts = {
        "coq_theorem": "GenericRead.any_start_six",
        "slot": "struct regmap.format.parse_inplace",
        "slot_evidence": "explicit constructor assignments precede device publication in reviewed regmap",
        "synchronous_spi": "completed transfer writes the caller data region under the Linux SPI contract",
        "owner_thread_window": "a synchronously nested read finishes before its managed parent IRQ can be released",
        "predicate_for_this_invocation": "not established for all calls to the shared poll function",
        "matched_nested_dispatch": source_matches(driver, r"\biio_trigger_poll_nested\s*\([^;]*\);"),
        "managed_parent_irqs": source_matches(driver, r"\bdevm_request_threaded_irq\s*\([^;]*\);"),
        "consumer_validation": source_matches(driver, r"\.validate_trigger\s*=\s*\w+"),
        "provider_validation": source_matches(driver, r"\.validate_device\s*=\s*\w+"),
    }
    exports = []
    lookups = []
    for owner in site["owners"]:
        name = re.escape(owner["function"])
        exports.extend(source_matches(driver, r"\bEXPORT_SYMBOL\w*\s*\(\s*" + name + r"\b[^;]*\);"))
        lookups.extend(owner["registry_lookup"])
    contracts["exported_probe"] = exports
    issues = []
    for lookup in lookups:
        if lookup.get("unnamed"):
            issues.append({"code": "unnamed_regmap_lookup", "source": lookup["source"], "line": lookup["line"],
                           "detail": "lookup returns the most recent matching map; object equality to the constructor is unproved"})
    if exports:
        issues.append({"code": "exported_probe_callers_not_closed", "source": site["source"], "line": exports[0]["line"],
                       "detail": "compiled frontend arguments do not constrain every caller of the exported probe"})
    registrations = [reg for owner in site["owners"] for reg in owner["registrations"]]
    if not registrations:
        return dict(result, reason="poll_registration_not_established")
    for reg in registrations:
        issues.append({"code": "shared_poll_lifetime_unproved", "source": reg["source"], "line": reg["line"],
                       "detail": "registration identifies the consumer, but cannot identify each invocation as coming from its live physical IRQ"})
    issues.append({"code": "detach_may_return_before_join", "source": "drivers/iio/industrialio-trigger.c",
                   "line": 343, "detail": "a failed trigger disable returns before the virtual IRQ is joined"})
    result.update(reason=issues[0]["code"], reason_detail=issues[0]["detail"], open_conditions=issues,
                  contracts=contracts)
    return result
