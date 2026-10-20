from __future__ import annotations

import argparse
import copy
from datetime import datetime
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any
import uuid

from jsonschema import Draft202012Validator, FormatChecker

# 허용된 루트 스키마 별칭 및 파일명 매핑
ALLOWED_ROOT_SCHEMAS: dict[str, str] = {
    "profile": "profile-1.1.schema.json",
    "profile-1.1": "profile-1.1.schema.json",
    "profile-1.1.schema.json": "profile-1.1.schema.json",
    "registry": "registry-1.1.schema.json",
    "registry-1.1": "registry-1.1.schema.json",
    "registry-1.1.schema.json": "registry-1.1.schema.json",
    "session": "session-1.1.schema.json",
    "session-1.1": "session-1.1.schema.json",
    "session-1.1.schema.json": "session-1.1.schema.json",
}
TRUSTED_SCHEMA_FILES: tuple[str, ...] = (
    "common-1.1.schema.json",
    "profile-1.1.schema.json",
    "registry-1.1.schema.json",
    "session-1.1.schema.json",
)
RFC3339_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$"
)
DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
NEGATION_TOKENS: tuple[str, ...] = ("불가", "없음", "미확인", "아님", "금지", "않음", "못함", "수 없")
SYN_RST_CLAIM_RE = re.compile(r"(?:SYN\s*송신|RST\s*수신).*?(?:확인|관찰|단정)")
FIREWALL_CLAIM_RE = re.compile(r"방화벽.*차단.*확정")
HOP_CLAIM_RE = re.compile(
    r"(?:마지막\s*응답\s*(?:hop|홉)|last\s*hop)\s*(?:=|\s*은|\s*는|\s*을|\s*를)?\s*차단\s*장비",
    re.IGNORECASE,
)


def _parse_rfc3339_aware(value: Any) -> datetime | None:
    """RFC3339 일시 문자열의 달력 날짜 및 시간대 오프셋 유효성을 검증한다."""
    if not isinstance(value, str) or not (m := RFC3339_RE.match(value)):
        return None
    date_part, time_part, frac_part, tz_part = m.groups()
    norm_tz = "+00:00" if tz_part == "Z" else tz_part
    norm_frac = f".{frac_part[:6].ljust(6, '0')}" if frac_part else ""
    try:
        dt = datetime.fromisoformat(f"{date_part}T{time_part}{norm_frac}{norm_tz}")
    except ValueError:
        return None
    return dt if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None else None


def _build_format_checker() -> FormatChecker:
    """RFC3339 date-time 및 UUID 검증기를 포함한 FormatChecker를 반환한다."""
    checker = FormatChecker()
    checker.checks("date-time")(lambda v: True if not isinstance(v, str) else _parse_rfc3339_aware(v) is not None)
    checker.checks("uuid")(lambda v: True if not isinstance(v, str) else _is_valid_uuid(v))
    return checker


def _is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _resolve_schema_filename(schema_name: str | Path, root_path: Path) -> str:
    """허용된 3종 루트 스키마만 수락하고 외부 경로 및 원격 참조를 차단한다."""
    raw = str(schema_name).strip()
    if not raw or "://" in raw or ".." in Path(raw).parts:
        raise ValueError(f"허용되지 않는 스키마 지정입니다: {schema_name}")
    path_obj = Path(raw)
    canonical = ALLOWED_ROOT_SCHEMAS.get(path_obj.name) or ALLOWED_ROOT_SCHEMAS.get(raw)
    if canonical is None:
        raise ValueError(f"허용된 루트 스키마(profile/registry/session)가 아닙니다: {schema_name}")
    if str(path_obj.parent) not in ("", "."):
        expected = (root_path / "schemas" / canonical).resolve()
        candidate = path_obj.resolve() if path_obj.is_absolute() else (root_path / path_obj).resolve()
        if candidate != expected:
            raise ValueError(f"신뢰된 로컬 schemas 경로 외부의 스키마입니다: {schema_name}")
    return canonical


def _load_trusted_assets(root_path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """계약 파일과 4개의 신뢰된 로컬 스키마 파일을 로드한다."""
    contract_path = root_path / "contracts" / "g1-interface-contract.json"
    if not contract_path.is_file():
        raise FileNotFoundError(f"계약 파일이 존재하지 않습니다: {contract_path}")
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    schemas: dict[str, dict[str, Any]] = {}
    for fname in TRUSTED_SCHEMA_FILES:
        fpath = root_path / "schemas" / fname
        if not fpath.is_file():
            raise FileNotFoundError(f"스키마 파일이 존재하지 않습니다: {fpath}")
        schemas[fname] = json.loads(fpath.read_text(encoding="utf-8"))
    return contract, schemas


def _rewrite_local_refs(node: Any) -> Any:
    """로컬 #/$defs 참조만 허용하고 비로컬 $ref 및 $id를 제거한다."""
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for k, v in node.items():
            if k == "$id":
                continue
            if k == "$ref":
                if not isinstance(v, str):
                    raise ValueError(f"유효하지 않은 $ref 형식입니다: {v!r}")
                if v == "profile-1.1.schema.json":
                    out[k] = "#/$defs/Profile"
                elif v.startswith("profile-1.1.schema.json#/"):
                    out[k] = "#/$defs/Profile/" + v.split("#/", 1)[1]
                elif v.startswith("common-1.1.schema.json#/"):
                    out[k] = "#/" + v.split("#/", 1)[1]
                elif v.startswith("#/"):
                    out[k] = v
                else:
                    raise ValueError(f"비로컬 $ref 참조가 거부되었습니다: {v}")
            else:
                out[k] = _rewrite_local_refs(v)
        return out
    return [_rewrite_local_refs(x) for x in node] if isinstance(node, list) else node


def _build_merged_schema(schema_file: str, schemas: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """선택된 루트 스키마를 깊은 복사하여 common $defs를 병합하고 로컬 참조로 변환한다."""
    root_copy = copy.deepcopy(schemas[schema_file])
    common_defs = copy.deepcopy(schemas["common-1.1.schema.json"].get("$defs", {}))
    profile_def = copy.deepcopy(schemas["profile-1.1.schema.json"])
    profile_def.pop("$id", None)
    profile_def.pop("$schema", None)
    common_defs["Profile"] = profile_def
    root_copy["$defs"] = {**common_defs, **copy.deepcopy(root_copy.get("$defs", {}))}
    return _rewrite_local_refs(root_copy)


def _validate_host_semantic(host: Any, path_label: str) -> list[str]:
    """단일 IPv4/IPv6 리터럴 또는 엄격한 ASCII 도메인 호스트명을 검증한다(DNS 미수행)."""
    if not isinstance(host, str) or not host or host != host.strip() or any(c.isspace() for c in host):
        return [f"{path_label}: 공백 없는 비어 있지 않은 호스트 문자열이 필요합니다: {host!r}"]
    if len(host) > 253 or any(t in host for t in ("://", "/", "\\", "@", "?", "#", ",", ";", "[", "]")):
        return [f"{path_label}: URL/경로/@/CIDR/목록 또는 길이 초과 호스트는 허용되지 않습니다: {host!r}"]
    if ":" in host:
        if "%" in host:
            return [f"{path_label}: IPv6 영역 식별자(%)는 허용되지 않습니다: {host!r}"]
        try:
            ipaddress.IPv6Address(host)
            return []
        except ValueError:
            return [f"{path_label}: 유효하지 않은 IPv6 리터럴 또는 포트 포함 호스트입니다: {host!r}"]
    try:
        ipaddress.IPv4Address(host)
        return []
    except ValueError:
        pass
    labels = host.split(".")
    if any(not lbl or not lbl.isascii() or len(lbl) > 63 or not DOMAIN_LABEL_RE.match(lbl) for lbl in labels):
        return [f"{path_label}: 유효하지 않은 ASCII 도메인 레이블입니다: {host!r}"]
    if labels[-1].isdigit():
        return [f"{path_label}: 잘못된 IPv4 주소이거나 숫자 전용 최상위 도메인입니다: {host!r}"]
    return []


def _validate_timestamps_recursive(node: Any, path_label: str) -> list[str]:
    """중첩된 모든 시각 필드의 RFC3339 달력 유효성과 시작·종료 시각 순서를 검증한다."""
    errors: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            cur = f"{path_label}.{k}" if path_label else k
            if (k in ("started_at_utc", "ended_at_utc") or k.endswith("_at_utc")) and v is not None:
                if _parse_rfc3339_aware(v) is None:
                    errors.append(f"{cur}: 유효하지 않은 RFC3339 일시(date-time)입니다: {v!r}")
            errors.extend(_validate_timestamps_recursive(v, cur))
        s_dt = _parse_rfc3339_aware(node.get("started_at_utc"))
        e_dt = _parse_rfc3339_aware(node.get("ended_at_utc"))
        if s_dt is not None and e_dt is not None and e_dt < s_dt:
            errors.append(f"{path_label or '$'}: ended_at_utc가 started_at_utc보다 앞설 수 없습니다.")
    elif isinstance(node, list):
        for i, item in enumerate(node):
            errors.extend(_validate_timestamps_recursive(item, f"{path_label}[{i}]"))
    return errors


def _validate_profile_semantic(
    profile: Any, contract_features: dict[str, dict[str, Any]], path_label: str
) -> list[str]:
    """프로파일의 알려진 기능 ID 고유성 및 대상 호스트 규칙을 검증한다."""
    if not isinstance(profile, dict):
        return [f"{path_label}: 프로파일은 객체여야 합니다."]
    errors: list[str] = []
    selected = profile.get("selected_features")
    if isinstance(selected, list):
        seen: set[str] = set()
        for i, fid in enumerate(selected):
            if not isinstance(fid, str) or fid not in contract_features:
                errors.append(f"{path_label}.selected_features[{i}]: 알 수 없는 feature_id입니다: {fid!r}")
            elif fid in seen:
                errors.append(f"{path_label}.selected_features[{i}]: 중복(duplicate)된 feature_id입니다: {fid!r}")
            else:
                seen.add(fid)
    target = profile.get("target")
    if isinstance(target, dict) and "host" in target:
        errors.extend(_validate_host_semantic(target.get("host"), f"{path_label}.target.host"))
    return errors


def _validate_session_semantic(session: Any, contract_features: dict[str, dict[str, Any]]) -> list[str]:
    """세션 증거 고유성·해석, 기능-그룹 매핑, 관찰 단정 금지 및 캡처 부재 시 합성 PCAP 금지를 검증한다."""
    if not isinstance(session, dict):
        return ["$: 세션 문서는 객체여야 합니다."]
    errors = _validate_timestamps_recursive(session, "$")
    profile = session.get("profile")
    if isinstance(profile, dict):
        errors.extend(_validate_profile_semantic(profile, contract_features, "$.profile"))

    evidence_by_id: dict[str, dict[str, Any]] = {}
    for i, ev in enumerate(session.get("evidence") if isinstance(session.get("evidence"), list) else []):
        if not isinstance(ev, dict):
            continue
        if not isinstance(ev.get("synthetic"), bool):
            errors.append(f"$.evidence[{i}].synthetic: boolean 플래그가 필수입니다.")
        ev_id = ev.get("evidence_id")
        if isinstance(ev_id, str) and ev_id:
            if ev_id in evidence_by_id:
                errors.append(f"$.evidence[{i}].evidence_id: 중복(duplicate)된 evidence_id입니다: {ev_id!r}")
            else:
                evidence_by_id[ev_id] = ev

    fr_by_id: dict[str, dict[str, Any]] = {}
    for i, fr in enumerate(session.get("feature_results") if isinstance(session.get("feature_results"), list) else []):
        if not isinstance(fr, dict):
            continue
        fid, gid = fr.get("feature_id"), fr.get("group_id")
        if isinstance(fid, str) and fid in contract_features:
            fr_by_id[fid] = fr
            if gid != contract_features[fid]["group_id"]:
                errors.append(f"$.feature_results[{i}]: {fid!r}의 group_id 매핑 불일치({gid!r}).")
        ev_ids = fr.get("evidence_ids") if isinstance(fr.get("evidence_ids"), list) else []
        for eid in ev_ids:
            if not isinstance(eid, str) or eid not in evidence_by_id:
                errors.append(f"$.feature_results[{i}].evidence_ids: 미해석(unresolved) evidence_id: {eid!r}")
        if fr.get("classification") == "OBSERVED" and not ev_ids:
            errors.append(f"$.feature_results[{i}]: OBSERVED 분류에는 비어 있지 않은 evidence_ids가 필요합니다.")

    for i, fd in enumerate(session.get("findings") if isinstance(session.get("findings"), list) else []):
        if not isinstance(fd, dict):
            continue
        ev_ids = fd.get("evidence_ids") if isinstance(fd.get("evidence_ids"), list) else []
        resolved = [evidence_by_id[eid] for eid in ev_ids if isinstance(eid, str) and eid in evidence_by_id]
        for eid in ev_ids:
            if not isinstance(eid, str) or eid not in evidence_by_id:
                errors.append(f"$.findings[{i}].evidence_ids: 미해석(unresolved) evidence_id: {eid!r}")
        if fd.get("classification") == "OBSERVED" and not ev_ids:
            errors.append(f"$.findings[{i}]: OBSERVED 분류에는 비어 있지 않은 evidence_ids가 필요합니다.")
        stmt = fd.get("statement")
        if isinstance(stmt, str) and not any(neg in stmt for neg in NEGATION_TOKENS):
            if SYN_RST_CLAIM_RE.search(stmt) and not any(e.get("kind") == "PACKET" for e in resolved):
                errors.append(f"$.findings[{i}].statement: SYN/RST 확인 단정에는 PACKET 증거가 필수입니다.")
            if FIREWALL_CLAIM_RE.search(stmt):
                errors.append(f"$.findings[{i}].statement: '방화벽 차단 확정' 단정은 허용되지 않습니다.")
            if HOP_CLAIM_RE.search(stmt):
                errors.append(f"$.findings[{i}].statement: '마지막 응답 HOP=차단 장비' 단정은 허용되지 않습니다.")

    packet_evs = [
        e for e in evidence_by_id.values()
        if e.get("kind") == "PACKET" or str(e.get("artifact_path") or "").lower().endswith((".pcap", ".pcapng"))
    ]
    cap_ok = isinstance(profile, dict) and profile.get("capture_approved") is True
    sel_set = set(profile.get("selected_features", [])) if isinstance(profile, dict) and isinstance(profile.get("selected_features"), list) else set()
    pkt_fr, imp_fr, exp_fr = fr_by_id.get("packet_capture"), fr_by_id.get("import_bundle"), fr_by_id.get("pcap_export")
    imp_ok = "import_bundle" in sel_set or (isinstance(imp_fr, dict) and imp_fr.get("status") == "PASS")
    cap_absent = (
        (isinstance(pkt_fr, dict) and pkt_fr.get("status") in ("SKIPPED_BY_USER", "UNAVAILABLE", "ERROR", "CANCELLED"))
        or (not cap_ok and not imp_ok)
    )
    if cap_absent and packet_evs:
        errors.append("$.evidence: 캡처 부재/미승인 상태에서 합성 PCAP 또는 PACKET 증거를 생성할 수 없습니다.")
    if isinstance(exp_fr, dict) and exp_fr.get("status") == "PASS":
        exp_eids = exp_fr.get("evidence_ids") if isinstance(exp_fr.get("evidence_ids"), list) else []
        if cap_absent or not any(isinstance(k, str) and k in evidence_by_id and evidence_by_id[k].get("kind") == "PACKET" for k in exp_eids):
            errors.append("$.feature_results[pcap_export]: 유효한 PACKET 증거 없이 pcap_export가 PASS일 수 없습니다.")
    return errors


def _validate_registry_semantic(registry: Any, contract_features: dict[str, dict[str, Any]]) -> list[str]:
    """레지스트리 23개 고유 기능, 고정 그룹/요구사항/의존성 및 의존성 그래프(누락·순환)를 검증한다."""
    if not isinstance(registry, list):
        return ["$: 레지스트리 문서는 배열(array)이어야 합니다."]
    errors: list[str] = []
    seen: dict[str, dict[str, Any]] = {}
    for i, entry in enumerate(registry):
        if not isinstance(entry, dict):
            errors.append(f"$[{i}]: 항목은 객체여야 합니다.")
            continue
        fid = entry.get("feature_id")
        if not isinstance(fid, str) or not fid:
            errors.append(f"$[{i}].feature_id: 유효한 feature_id 문자열이 필요합니다.")
            continue
        if fid in seen:
            errors.append(f"$[{i}].feature_id: 중복(duplicate)된 feature_id입니다: {fid!r}")
            continue
        seen[fid] = entry
        if fid not in contract_features:
            errors.append(f"$[{i}].feature_id: 계약에 없는 알 수 없는 feature_id입니다: {fid!r}")
            continue
        exp = contract_features[fid]
        for field in ("group_id", "requirements", "dependencies"):
            if entry.get(field) != exp[field]:
                errors.append(f"$[{i}].{field}: {fid!r}의 {field}가 계약 고정값과 불일치합니다.")

    missing_ids = set(contract_features) - set(seen)
    if missing_ids or len(registry) != len(contract_features):
        errors.append(f"$: 계약의 23개 고유 feature_id가 모두 필요합니다(누락: {sorted(missing_ids)}).")

    dep_graph: dict[str, list[str]] = {}
    for fid, entry in seen.items():
        deps = entry.get("dependencies") if isinstance(entry.get("dependencies"), list) else []
        valid_deps: list[str] = []
        for dep in deps:
            if not isinstance(dep, str) or dep not in seen or dep not in contract_features:
                errors.append(f"$[{fid}].dependencies: 존재하지 않는 의존성(missing dependency) 노드: {dep!r}")
            else:
                valid_deps.append(dep)
        dep_graph[fid] = valid_deps

    state: dict[str, int] = {}

    def _visit(node: str) -> bool:
        state[node] = 1
        for nxt in dep_graph.get(node, []):
            if state.get(nxt, 0) == 1 or (state.get(nxt, 0) == 0 and _visit(nxt)):
                return True
        state[node] = 2
        return False

    for fid in dep_graph:
        if state.get(fid, 0) == 0 and _visit(fid):
            errors.append(f"$[{fid}].dependencies: 의존성 순환(dependency cycle)이 감지되었습니다.")
            break
    return errors


def validate_document(
    instance: Any, schema_name: str | Path, root: str | Path | None = None
) -> list[str]:
    """문서를 지정된 스키마(profile/registry/session)와 G1 계약 의미 규칙으로 검증하여 오류 목록을 반환한다."""
    root_path = Path(root).resolve() if root is not None else Path(__file__).resolve().parents[1]
    schema_file = _resolve_schema_filename(schema_name, root_path)
    contract, schemas = _load_trusted_assets(root_path)
    contract_features = {f["feature_id"]: f for f in contract.get("features", []) if isinstance(f, dict)}

    errors: list[str] = []
    if schema_file == "registry-1.1.schema.json" and not isinstance(instance, list):
        errors.append("$: registry 문서는 루트가 배열(array)이어야 합니다.")
    elif schema_file != "registry-1.1.schema.json" and not isinstance(instance, dict):
        errors.append(f"$: {schema_file} 문서는 루트가 객체(object)여야 합니다.")

    merged = _build_merged_schema(schema_file, schemas)
    validator = Draft202012Validator(merged, format_checker=_build_format_checker())
    for err in sorted(validator.iter_errors(instance), key=lambda e: ([str(p) for p in e.absolute_path], e.message)):
        loc = ".".join(str(p) for p in err.absolute_path) or "$"
        errors.append(f"{loc}: {err.message}")

    if schema_file == "profile-1.1.schema.json":
        errors.extend(_validate_profile_semantic(instance, contract_features, "$"))
    elif schema_file == "session-1.1.schema.json":
        errors.extend(_validate_session_semantic(instance, contract_features))
    else:
        errors.extend(_validate_registry_semantic(instance, contract_features))
    return errors


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(f"CLI 인자 오류: {message}")


def main(argv: list[str] | None = None) -> int:
    """CLI 진입점: JSON {valid, errors}를 출력하고 종료 코드(0=유효, 1=무효, 2=사용법/로드 오류)를 반환한다."""
    parser = _JsonArgumentParser(add_help=True)
    parser.add_argument("--schema", help="허용된 로컬 스키마(profile/registry/session)")
    parser.add_argument("--instance", help="검증할 JSON 파일 경로")
    parser.add_argument("--root", default=None, help="프로젝트 루트 경로")
    parser.add_argument("--all", action="store_true", dest="run_all", help="매니페스트 전체 검증(미구현)")
    try:
        args = parser.parse_args(argv)
        if args.run_all:
            raise ValueError("--all 옵션은 부모 매니페스트 생성 전까지 지원되지 않습니다.")
        if not args.schema or not args.instance:
            raise ValueError("--schema 및 --instance 인자가 모두 필요합니다.")
        if "://" in str(args.instance):
            raise ValueError("원격 URL 인스턴스는 허용되지 않습니다.")
        inst_path = Path(args.instance)
        if not inst_path.is_file():
            raise FileNotFoundError(f"인스턴스 파일을 찾을 수 없습니다: {inst_path}")
        instance_data = json.loads(inst_path.read_text(encoding="utf-8"))
        errors = validate_document(instance_data, args.schema, root=args.root)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, ensure_ascii=False))
        return 2
    valid = len(errors) == 0
    print(json.dumps({"valid": valid, "errors": errors}, ensure_ascii=False))
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
