#!/usr/bin/env python3
"""
Merge Chrome (Windows) Bookmarks JSON files into the target browser's
`Bookmarks` file on Linux. Both Chrome and Brave use the same JSON format
(roots.bookmark_bar / other / synced, Chromium-time dates), so the merge is
a matter of re-identifying nodes: fresh numeric ids and guids must be used,
the source "checksum" field must be dropped (the target browser recomputes
it on load and repairs silently), and the imported nodes go under wrapper
folders so they are easy to find (e.g. "Chrome Default").

Requirement: the target browser must be CLOSED while writing the file.

Usage:
    python3 merge_bookmarks.py \
        --src ../Chrome/Default --src "../Chrome/Profile 1" \
        --dst ~/.config/BraveSoftware/Brave-Browser/Default/Bookmarks
"""

import argparse
import json
import os
import uuid


def walk_max_id(node, state):
    if isinstance(node, dict) and "id" in node:
        try:
            state["max_id"] = max(state["max_id"], int(node["id"]))
        except (TypeError, ValueError):
            pass
    for child in node.get("children", []) or []:
        walk_max_id(child, state)


def clean_node(n, state, wrapper_name=None):
    """Re-identify a Chrome node for the target: new id+guid, no meta."""
    out = {"date_added": n.get("date_added", "0"),
           "name": wrapper_name if wrapper_name else n.get("name", "")}
    if wrapper_name:
        out["type"] = "folder"
        out["date_modified"] = "0"
        out["children"] = []
        return out
    t = n.get("type")
    if t == "url":
        out.update(type="url", url=n.get("url", ""))
    elif t == "folder":
        out["date_modified"] = n.get("date_modified", "0")
        out.update(type="folder",
                   children=[c for c in (clean_node(x, state)
                                         for x in n.get("children", []) or [])
                             if c])
    else:
        return None
    out["date_last_used"] = n.get("date_last_used", "0")
    state["next_id"] += 1
    out["id"] = str(state["next_id"])
    out["guid"] = str(uuid.uuid4())
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", action="append", required=True,
                    help="folder with Chrome's Bookmarks.json (repeatable)")
    ap.add_argument("--dst", required=True, help="target Bookmarks file")
    args = ap.parse_args()

    dst_path = os.path.expanduser(args.dst)
    data = json.load(open(dst_path, encoding="utf-8"))
    roots = data["roots"]

    state = {"max_id": 0, "next_id": 0}
    for r in roots.values():
        walk_max_id(r, state)
    state["next_id"] = state["max_id"] + 100

    for src in args.src:
        src_path = os.path.expanduser(os.path.join(src, "Bookmarks.json"))
        chrome = json.load(open(src_path, encoding="utf-8"))
        prof = os.path.basename(src.rstrip("/")) or "Default"
        wrapper_uuid = str(uuid.uuid4())
        state["next_id"] += 1
        wrap_id = str(state["next_id"])
        wrap = {"children": [], "date_added": "0", "date_modified": "0",
                "date_last_used": "0", "id": wrap_id, "guid": wrapper_uuid,
                "name": f"Chrome {prof}", "type": "folder"}
        bar = chrome["roots"].get("bookmark_bar", {}).get("children", []) or []
        oth = chrome["roots"].get("other", {}).get("children", []) or []
        wrap["children"] = [c for c in (clean_node(x, state) for x in bar + oth) if c]
        if wrap["children"]:
            roots["bookmark_bar"].setdefault("children", []).append(wrap)
            print(f"added folder 'Chrome {prof}': {len(wrap['children'])} top nodes")

    data.pop("checksum", None)  # target recomputes and repairs silently
    with open(dst_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=3)
    print(f"Bookmarks written: {dst_path}")


if __name__ == "__main__":
    main()
