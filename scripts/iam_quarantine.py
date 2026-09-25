#!/usr/bin/env python3
"""IAM account quarantine / release for incident response (DR-TECH-005, DR-PLAY-005).

quarantine: attaches a deny-all inline policy to every IAM role, user, and group in
the account, except:
  - the role this workflow itself assumed (excluded automatically, so `release` can
    still run afterward)
  - AWS service-linked roles (path starts with /aws-service-role/): quarantining one
    can break AWS's own account-level functionality (Support, Trusted Advisor, etc.)
  - anything explicitly named in --exclude-roles / --exclude-users / --exclude-groups
    (break-glass identities, logging/security roles)
  - a group whose membership includes an excluded user (denying the group would deny
    that user too, defeating the exclusion)
This is IAM-only: it cannot deny the account root user, and it does not cover
IAM Identity Center permission sets or anything reachable outside IAM (e.g. resource
policies granting a different account access directly). Use an Organizations SCP for
an account-wide guarantee that includes root.

release: removes that same inline policy from anything that has it, including
identities added to an exclusion list after they were quarantined. Idempotent: an
identity that was never quarantined (or already released) is a no-op, not an error.

Called by .github/workflows/dr-tech005-quarantine-scps.yml as:
  python iam_quarantine.py <quarantine|release> --account-id <id> [--dry-run]
Exclusion lists come from the EXCLUDED_ROLES / EXCLUDED_USERS / EXCLUDED_GROUPS
environment variables (comma-separated names), matching that workflow's env block.
"""

import argparse
import json
import os
import sys

import boto3
from botocore.exceptions import ClientError

DENY_ALL_POLICY_NAME = "dr-tech005-quarantine-deny-all"
DENY_ALL_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "QuarantineDenyAll",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
)


def _names_from_env(var_name):
    raw = os.environ.get(var_name, "")
    return {name.strip() for name in raw.split(",") if name.strip()}


def _current_role_name(sts_client):
    """Name of the role this process itself assumed, so it never locks itself out."""
    arn = sts_client.get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        return arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
    if ":role/" in arn:
        return arn.split(":role/", 1)[1]
    return None


def _list_all(iam_client, paginator_name, result_key):
    items = []
    for page in iam_client.get_paginator(paginator_name).paginate():
        items.extend(page[result_key])
    return items


def _group_members(iam_client, group_name):
    members = []
    for page in iam_client.get_paginator("get_group").paginate(GroupName=group_name):
        members.extend(user["UserName"] for user in page["Users"])
    return members


def _log(action, kind, name, dry_run, reason=None):
    if reason:
        print(f"  skip {kind} {name} ({reason})")
        return
    prefix = "[dry-run] would " if dry_run else ""
    verb = "quarantine" if action == "quarantine" else "release"
    print(f"  {prefix}{verb} {kind} {name}")


def _apply_deny_all(put_fn, delete_fn, name_kwarg, name, action, dry_run):
    if dry_run:
        return
    if action == "quarantine":
        put_fn(**{name_kwarg: name}, PolicyName=DENY_ALL_POLICY_NAME, PolicyDocument=DENY_ALL_POLICY_DOCUMENT)
    else:
        try:
            delete_fn(**{name_kwarg: name}, PolicyName=DENY_ALL_POLICY_NAME)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise


def process_roles(iam, action, excluded, dry_run):
    roles = _list_all(iam, "list_roles", "Roles")
    print(f"Roles: {len(roles)} total, {len(excluded)} excluded")
    for role in roles:
        name = role["RoleName"]
        # Exclusion only suppresses quarantine; release always tries to remove the
        # policy, so a role added to the exclusion list after being quarantined still
        # gets un-quarantined.
        if action == "quarantine" and name in excluded:
            _log(action, "role", name, dry_run, reason="excluded")
            continue
        if role.get("Path", "/").startswith("/aws-service-role/"):
            _log(action, "role", name, dry_run, reason="AWS service-linked role")
            continue
        _log(action, "role", name, dry_run)
        _apply_deny_all(iam.put_role_policy, iam.delete_role_policy, "RoleName", name, action, dry_run)


def process_users(iam, action, excluded, dry_run):
    users = _list_all(iam, "list_users", "Users")
    print(f"Users: {len(users)} total, {len(excluded)} excluded")
    for user in users:
        name = user["UserName"]
        if action == "quarantine" and name in excluded:
            _log(action, "user", name, dry_run, reason="excluded")
            continue
        _log(action, "user", name, dry_run)
        _apply_deny_all(iam.put_user_policy, iam.delete_user_policy, "UserName", name, action, dry_run)


def process_groups(iam, action, excluded, excluded_users, dry_run):
    groups = _list_all(iam, "list_groups", "Groups")
    print(f"Groups: {len(groups)} total, {len(excluded)} excluded")
    for group in groups:
        name = group["GroupName"]
        if action == "quarantine":
            if name in excluded:
                _log(action, "group", name, dry_run, reason="excluded")
                continue
            overlap = excluded_users & set(_group_members(iam, name))
            if overlap:
                _log(action, "group", name, dry_run, reason=f"contains excluded user(s): {', '.join(sorted(overlap))}")
                continue
        _log(action, "group", name, dry_run)
        _apply_deny_all(iam.put_group_policy, iam.delete_group_policy, "GroupName", name, action, dry_run)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["quarantine", "release"])
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    sts = boto3.client("sts")
    caller_account = sts.get_caller_identity()["Account"]
    if caller_account != args.account_id:
        print(
            f"::error::Assumed role's account ({caller_account}) does not match "
            f"--account-id ({args.account_id}); refusing to proceed.",
            file=sys.stderr,
        )
        sys.exit(1)

    excluded_roles = _names_from_env("EXCLUDED_ROLES")
    current_role = _current_role_name(sts)
    if current_role:
        excluded_roles.add(current_role)
    excluded_users = _names_from_env("EXCLUDED_USERS")
    excluded_groups = _names_from_env("EXCLUDED_GROUPS")

    iam = boto3.client("iam")

    process_roles(iam, args.action, excluded_roles, args.dry_run)
    process_users(iam, args.action, excluded_users, args.dry_run)
    process_groups(iam, args.action, excluded_groups, excluded_users, args.dry_run)

    print(f"Done: {args.action}{' (dry run, nothing changed)' if args.dry_run else ''}")


if __name__ == "__main__":
    main()
