"""Per-cell tool implementations + LiteLLM tool-schema dicts .

Clean-room re-implementation of the 14 email/calendar/file tools documented in
``Janus/src/tools/{email,calendar,file}_tools.py``. Each tool reads + mutates
the per-cell seed data passed in at construction (no globals), so cells are
isolated. Output strings are matched to Janus so the LLM sees identical output.

The LiteLLM/OpenAI tool-schema dicts (``as_litellm_tools``) are built from the
same metadata Janus ships in ``src/tools/metadata/*.json``; they are JSON tool
descriptors, not code, so they are not "vendored code" — they describe the tool
surface to the LLM.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

__all__ = ["Tools", "TOOL_REGISTRY", "ToolHandler"]


@dataclass
class Tools:
    """Holds per-cell mutable scenario data and exposes the 14 tools as methods."""

    emails: list[dict[str, Any]] = field(default_factory=list)
    calendar_events: list[dict[str, Any]] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)

    # ---- email ---------------------------------------------------------

    def list_emails(self, unread: bool = False) -> str:
        items = self.emails
        if unread:
            items = [e for e in items if not e.get("read", False)]
        if not items:
            return "No unread emails found." if unread else "No emails found."
        out = f"Found {len(items)} email(s):\n\n"
        for email in reversed(items):
            out += (
                f"Email ID: {email['id']}\n"
                f"From: {email['from']}\n"
                f"To: {email['to']}\n"
                f"Subject: {email['subject']}\n"
                f"Sent: {email['timestamp']}\n"
                f"Body: {email['body']}\n" + "-" * 40 + "\n\n"
            )
        return out.rstrip()

    def search_emails(self, **kwargs: Any) -> str:
        sender_filter = str(kwargs.get("from", ""))
        items = self.emails
        if not items:
            return "No emails found."
        filtered = [e for e in items if _matches_sender(sender_filter, e.get("from", ""))]
        if not filtered:
            return f"No emails found from '{sender_filter}'."
        out = f"Found {len(filtered)} email(s):\n\n"
        for email in reversed(filtered):
            out += (
                f"Email ID: {email['id']}\n"
                f"From: {email['from']}\n"
                f"To: {email['to']}\n"
                f"Subject: {email['subject']}\n"
                f"Sent: {email['timestamp']}\n"
                f"Body: {email['body']}\n" + "-" * 40 + "\n\n"
            )
        return out.rstrip()

    def get_email(self, **kwargs: Any) -> str:
        email_id = kwargs.get("id")
        sender_filter = str(kwargs.get("from", ""))
        items = self.emails
        if not items:
            return "No emails found."
        match = None
        if email_id is not None:
            match = next((e for e in items if str(e["id"]) == str(email_id)), None)
        elif sender_filter:
            matching = [e for e in items if _matches_sender(sender_filter, e.get("from", ""))]
            if matching:
                match = matching[-1]
        else:
            return "Provide either id or from to get an email."
        if not match:
            return "Email not found."
        match["read"] = True
        return (
            "Email details:\n\n"
            f"Email ID: {match['id']}\n"
            f"From: {match['from']}\n"
            f"To: {match['to']}\n"
            f"Subject: {match['subject']}\n"
            f"Sent: {match['timestamp']}\n"
            f"Body: {match['body']}"
        )

    def send_email(
        self, to: str, subject: str, body: str, attachments: list[Any] | None = None
    ) -> str:
        next_id = max((e["id"] for e in self.emails), default=0) + 1
        email = {
            "id": next_id,
            "from": "user@example.com",
            "to": to,
            "subject": subject,
            "body": body,
            "timestamp": datetime.now().isoformat(),
            "status": "sent",
            "read": True,
            "attachments": attachments or [],
        }
        self.emails.append(email)
        attachment_note = f"\nAttachments: {len(attachments)} file(s)" if attachments else ""
        return (
            "Email sent successfully.\n\n"
            f"Email ID: {email['id']}\n"
            f"From: {email['from']}\n"
            f"To: {email['to']}\n"
            f"Subject: {email['subject']}\n"
            f"Sent at: {email['timestamp']}"
            f"{attachment_note}"
            "\n\n"
            f"Message body:\n{body}"
        )

    def delete_email(self, id: str) -> str:  # noqa: A002 - matches Janus signature
        match = next((e for e in self.emails if str(e["id"]) == str(id)), None)
        if not match:
            return f"Email with ID {id} not found."
        self.emails[:] = [e for e in self.emails if str(e["id"]) != str(id)]
        return f"Email with ID {id} deleted."

    # ---- calendar ------------------------------------------------------

    def list_calendar_events(self, date: str) -> str:
        events = [e for e in self.calendar_events if e.get("date") == date]
        if not events:
            return f"No events found for {date}."
        events = sorted(events, key=lambda e: e["time"])
        out = f"Found {len(events)} event(s) on {date}:\n\n"
        for event in events:
            out += _format_event(event) + "\n" + "-" * 40 + "\n\n"
        return out.rstrip()

    def check_calendar_availability(self, date: str, time: str) -> str:
        target = _parse_dt(date, time)
        for event in self.calendar_events:
            if event.get("date") != date:
                continue
            start = _parse_dt(event["date"], event["time"])
            dur = _event_duration(event)
            end = start + timedelta(minutes=dur)
            if start <= target < end:
                return f"Not available at {date} {time}."
        return f"Available at {date} {time}."

    def create_calendar_event(
        self,
        title: str,
        date: str,
        time: str,
        description: str = "",
        participants: list[str] | None = None,
    ) -> str:
        next_id = max((e["id"] for e in self.calendar_events), default=0) + 1
        event = {
            "id": next_id,
            "title": title,
            "date": date,
            "time": time,
            "description": description,
            "participants": participants or [],
            "duration_minutes": 60,
        }
        self.calendar_events.append(event)
        return "Calendar event created successfully.\n\n" + _format_event(event)

    def get_calendar_event(self, title: str) -> str:
        matches = [e for e in self.calendar_events if e.get("title") == title]
        if not matches:
            return f"No events found with title '{title}'."
        return _format_event(matches[-1])

    def add_calendar_participants(self, title: str, participants: list[str]) -> str:
        event = next((e for e in self.calendar_events if e["title"] == title), None)
        if not event:
            return f"No events found with title '{title}'."
        event["participants"] = sorted(set(event.get("participants", []) + participants))
        return "Participants added.\n\n" + _format_event(event)

    def add_calendar_participant(self, title: str, participant: str) -> str:
        return self.add_calendar_participants(title=title, participants=[participant])

    # ---- file ----------------------------------------------------------

    def list_files(self) -> str:
        files = self.files
        if not files:
            return "No files found."
        out = f"Found {len(files)} file(s):\n\n"
        for f in files:
            out += f"File ID: {f['id']}\nPath: {f['path']}\n" + "-" * 40 + "\n\n"
        return out.rstrip()

    def get_file(self, path: str | None = None, id: str | None = None) -> str:  # noqa: A002
        match = None
        if id is not None:
            match = next((f for f in self.files if str(f.get("id")) == str(id)), None)
        if match is None and path:
            match = next((f for f in self.files if f.get("path") == path), None)
        elif match is None and id is None and not path:
            return "Provide either path or id to get a file."
        if not match:
            return "File not found."
        # Janus returns a dict for the tool layer; we serialize for the LLM.
        return json.dumps(
            {"id": match.get("id"), "path": match.get("path"), "content": match.get("content", "")}
        )

    def delete_file(self, id: str) -> str:  # noqa: A002
        match = next((f for f in self.files if str(f.get("id")) == str(id)), None)
        if not match:
            return f"File with ID {id} not found."
        self.files[:] = [f for f in self.files if str(f.get("id")) != str(id)]
        return f"File with ID {id} deleted."


# ---- (tool_name, action, fn, json-schema-params) registry --------------------
# Order matters; matches the metadata JSON ordering for parity.

ToolHandler = Callable[..., str]


@dataclass(frozen=True)
class ToolSpec:
    fn_name: str
    tool_name: str  # the "category" Janus matches policies against
    action: str
    description: str
    params: Mapping[str, Mapping[str, Any]]  # param_name -> {type, description, required}


TOOL_REGISTRY: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_emails",
        "email",
        "list",
        "List emails, optionally filtering for unread messages",
        {
            "unread": {
                "type": "boolean",
                "description": "Filter for unread messages",
                "required": False,
            }
        },
    ),
    ToolSpec(
        "search_emails",
        "email",
        "search",
        "Search emails by sender",
        {
            "from": {
                "type": "string",
                "description": "Sender filter (substring match)",
                "required": False,
            }
        },
    ),
    ToolSpec(
        "get_email",
        "email",
        "get",
        "Get an email by id or sender",
        {
            "id": {"type": "string", "description": "Email identifier", "required": False},
            "from": {
                "type": "string",
                "description": "Sender filter (substring match)",
                "required": False,
            },
        },
    ),
    ToolSpec(
        "send_email",
        "email",
        "send",
        "Send an email to one recipient per call using values from user input or tool outputs in this run.",
        {
            "to": {
                "type": "string",
                "description": "Single recipient email address for this call",
                "required": True,
            },
            "subject": {"type": "string", "description": "Email subject line", "required": True},
            "body": {"type": "string", "description": "Email body content", "required": True},
            "attachments": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filenames to attach",
                "required": False,
            },
        },
    ),
    ToolSpec(
        "delete_email",
        "email",
        "delete",
        "Delete an email by id",
        {"id": {"type": "string", "description": "Email identifier to delete", "required": True}},
    ),
    ToolSpec(
        "list_calendar_events",
        "calendar",
        "list",
        "List calendar events for a specific date",
        {"date": {"type": "string", "description": "Date (YYYY-MM-DD)", "required": True}},
    ),
    ToolSpec(
        "check_calendar_availability",
        "calendar",
        "check_availability",
        "Check if a time slot is available",
        {
            "date": {"type": "string", "description": "Date (YYYY-MM-DD)", "required": True},
            "time": {"type": "string", "description": "Time (HH:MM)", "required": True},
        },
    ),
    ToolSpec(
        "create_calendar_event",
        "calendar",
        "create",
        "Create a new calendar event",
        {
            "title": {"type": "string", "description": "Event title", "required": True},
            "date": {"type": "string", "description": "Event date (YYYY-MM-DD)", "required": True},
            "time": {"type": "string", "description": "Event start time (HH:MM)", "required": True},
            "description": {
                "type": "string",
                "description": "Event description",
                "required": False,
            },
            "participants": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Attendee email addresses",
                "required": False,
            },
        },
    ),
    ToolSpec(
        "get_calendar_event",
        "calendar",
        "get",
        "Get a calendar event by title",
        {"title": {"type": "string", "description": "Event title to retrieve", "required": True}},
    ),
    ToolSpec(
        "add_calendar_participants",
        "calendar",
        "add_participants",
        "Add multiple participants to the event matching the title",
        {
            "title": {
                "type": "string",
                "description": "Exact title of the event to update",
                "required": True,
            },
            "participants": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Attendee email addresses to add",
                "required": True,
            },
        },
    ),
    ToolSpec(
        "add_calendar_participant",
        "calendar",
        "add_participant",
        "Add a single participant to the event matching the title",
        {
            "title": {
                "type": "string",
                "description": "Exact title of the event to update",
                "required": True,
            },
            "participant": {
                "type": "string",
                "description": "Attendee email address to add",
                "required": True,
            },
        },
    ),
    ToolSpec("list_files", "file", "list", "List available files", {}),
    ToolSpec(
        "get_file",
        "file",
        "get",
        "Get a file by exact path or id from user input or prior tool outputs in this run.",
        {
            "path": {
                "type": "string",
                "description": "Exact file path to fetch",
                "required": False,
            },
            "id": {"type": "string", "description": "File identifier to fetch", "required": False},
        },
    ),
    ToolSpec(
        "delete_file",
        "file",
        "delete",
        "Delete a file by id",
        {"id": {"type": "string", "description": "File identifier to delete", "required": True}},
    ),
)


def as_litellm_tools() -> list[dict[str, Any]]:
    """Build the OpenAI/LiteLLM tool-schema list for the agent LLM."""
    out: list[dict[str, Any]] = []
    for spec in TOOL_REGISTRY:
        properties: dict[str, Any] = {}
        required: list[str] = []
        for name, meta in spec.params.items():
            properties[name] = {"type": meta["type"], "description": meta["description"]}
            if meta.get("required"):
                required.append(name)
        out.append(
            {
                "type": "function",
                "function": {
                    "name": spec.fn_name,
                    "description": spec.description,
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required,
                    },
                },
            }
        )
    return out


def dispatch(tools: Tools, fn_name: str, args: Mapping[str, Any]) -> str:
    """Invoke the named tool on the per-cell ``tools`` instance."""
    handler: Callable[..., Any] = getattr(tools, fn_name)
    return str(handler(**dict(args)))


# ---- helpers ---------------------------------------------------------------


def _matches_sender(sender_filter: str, sender: str) -> bool:
    if not sender_filter:
        return True
    return sender_filter.lower() in sender.lower()


def _parse_dt(date: str, time: str) -> datetime:
    return datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M")


def _event_duration(event: Mapping[str, Any]) -> int:
    duration = event.get("duration_minutes")
    if duration is not None:
        return int(duration)
    if event.get("end_time"):
        start = _parse_dt(event["date"], event["time"])
        end = _parse_dt(event["date"], event["end_time"])
        return int((end - start).total_seconds() // 60)
    return 60


def _format_event(event: Mapping[str, Any]) -> str:
    duration = _event_duration(event)
    end_time = ""
    try:
        start = _parse_dt(event["date"], event["time"])
        end = start + timedelta(minutes=duration)
        end_time = end.strftime("%H:%M")
    except (KeyError, ValueError):
        end_time = ""
    return (
        f"Event ID: {event['id']}\n"
        f"Title: {event['title']}\n"
        f"Date: {event['date']}\n"
        f"Time: {event['time']}\n"
        f"Duration (minutes): {duration}\n"
        f"End Time: {end_time if end_time else 'Unknown'}\n"
        f"Description: {event['description']}\n"
        f"Participants: {', '.join(event['participants']) if event.get('participants') else 'None'}"
    )
