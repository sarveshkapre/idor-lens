from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .jsonl import open_text_out


def spec_schema() -> dict[str, Any]:
    non_empty_str: dict[str, Any] = {"type": "string", "minLength": 1}
    str_map: dict[str, Any] = {
        "type": "object",
        "additionalProperties": {"type": "string"},
    }
    cookie_map: dict[str, Any] = {
        "type": "object",
        "propertyNames": {"type": "string", "minLength": 1},
        "additionalProperties": {"type": "string"},
    }

    body_mode: dict[str, Any] = {"type": "string", "enum": ["json", "form", "raw"]}

    preflight_step: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["path"],
        "properties": {
            "path": non_empty_str,
            "method": non_empty_str,
            "timeout": {"type": "number", "exclusiveMinimum": 0},
            "headers": str_map,
            "content_type": non_empty_str,
            "body_mode": body_mode,
            "body": {},
        },
        "allOf": [
            {
                "if": {"properties": {"body_mode": {"const": "form"}}},
                "then": {
                    "properties": {"body": {"type": ["object", "null"], "additionalProperties": {}}}
                },
            },
            {
                "if": {"properties": {"body_mode": {"const": "raw"}}},
                "then": {"properties": {"body": {"type": ["string", "null"]}}},
            },
        ],
    }

    role_schema: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "auth": non_empty_str,
            "auth_file": non_empty_str,
            "headers": str_map,
            "cookies": cookie_map,
            "preflight": {"type": "array", "items": preflight_step},
            "timeout": {"type": "number", "exclusiveMinimum": 0},
            "verify_tls": {"type": "boolean"},
            "follow_redirects": {"type": "boolean"},
            "retries": {"type": "integer", "minimum": 0},
            "retry_backoff_s": {"type": "number", "minimum": 0},
            "proxy": non_empty_str,
        },
        # Disallow setting both auth and auth_file.
        "allOf": [{"not": {"required": ["auth", "auth_file"]}}],
    }

    endpoint_schema: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["path"],
        "properties": {
            "name": non_empty_str,
            "path": non_empty_str,
            "method": non_empty_str,
            "headers": str_map,
            "victim_headers": str_map,
            "attacker_headers": str_map,
            "cookies": cookie_map,
            "victim_cookies": cookie_map,
            "attacker_cookies": cookie_map,
            "timeout": {"type": "number", "exclusiveMinimum": 0},
            "victim_timeout": {"type": "number", "exclusiveMinimum": 0},
            "attacker_timeout": {"type": "number", "exclusiveMinimum": 0},
            "follow_redirects": {"type": "boolean"},
            "victim_follow_redirects": {"type": "boolean"},
            "attacker_follow_redirects": {"type": "boolean"},
            "content_type": non_empty_str,
            "victim_content_type": non_empty_str,
            "attacker_content_type": non_empty_str,
            "deny_contains": {"type": "array", "items": non_empty_str},
            "deny_regex": {"type": "array", "items": non_empty_str},
            "allow_contains": {"type": "array", "items": non_empty_str},
            "allow_regex": {"type": "array", "items": non_empty_str},
            "json_ignore_paths": {"type": "array", "items": non_empty_str},
            "matrix": {
                "type": "object",
                "propertyNames": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"},
                "additionalProperties": {"type": "array", "items": {}, "minItems": 1},
            },
            "body_mode": body_mode,
            "victim_body_mode": body_mode,
            "attacker_body_mode": body_mode,
            "victim_body": {},
            "attacker_body": {},
        },
        "allOf": [
            {
                "if": {"properties": {"victim_body_mode": {"const": "form"}}},
                "then": {
                    "properties": {
                        "victim_body": {"type": ["object", "null"], "additionalProperties": {}}
                    }
                },
            },
            {
                "if": {"properties": {"victim_body_mode": {"const": "raw"}}},
                "then": {"properties": {"victim_body": {"type": ["string", "null"]}}},
            },
            {
                "if": {"properties": {"attacker_body_mode": {"const": "form"}}},
                "then": {
                    "properties": {
                        "attacker_body": {"type": ["object", "null"], "additionalProperties": {}}
                    }
                },
            },
            {
                "if": {"properties": {"attacker_body_mode": {"const": "raw"}}},
                "then": {"properties": {"attacker_body": {"type": ["string", "null"]}}},
            },
        ],
    }

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "IDOR Lens Spec",
        "type": "object",
        "additionalProperties": False,
        "required": ["base_url", "endpoints"],
        "properties": {
            "base_url": non_empty_str,
            "verify_tls": {"type": "boolean"},
            "proxy": non_empty_str,
            "follow_redirects": {"type": "boolean"},
            "retries": {"type": "integer", "minimum": 0},
            "retry_backoff_s": {"type": "number", "minimum": 0},
            "retry_statuses": {"type": "array", "items": {"type": "integer"}},
            "deny_contains": {"type": "array", "items": non_empty_str},
            "deny_regex": {"type": "array", "items": non_empty_str},
            "allow_contains": {"type": "array", "items": non_empty_str},
            "allow_regex": {"type": "array", "items": non_empty_str},
            "json_ignore_paths": {"type": "array", "items": non_empty_str},
            "victim": role_schema,
            "attacker": role_schema,
            "endpoints": {"type": "array", "items": endpoint_schema, "minItems": 1},
        },
    }


def write_spec_schema(out_path: Path) -> None:
    schema = spec_schema()
    with open_text_out(out_path) as out:
        out.write(json.dumps(schema, indent=2, sort_keys=True))
        out.write("\n")
